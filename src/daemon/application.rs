//! Process-level daemon lifecycle helpers.

use super::circuit_reconciler::{
    CircuitReconcileContext, open_configured_circuit, start as start_circuit_reconciler,
};
use super::control_handler::wait_for_any_link;
use super::link_lifecycle::start_links;
use super::network_lifecycle::NetworkResources;
use super::network_lifecycle::{managed_overlay_prefixes, sync_managed_overlay_routes};
use super::route_snapshot::build_route_snapshot;
#[cfg(target_os = "linux")]
use super::support::healthy_route_prefixes;
use super::support::{collect_underlay_endpoints, initial_tun_mtu};
use anyhow::{Context, Result};
use std::{collections::HashSet, future::Future, path::PathBuf, sync::Arc};
use tinect::{
    config::Config,
    dataplane, platform,
    runtime::{DaemonSupervisor, Runtime},
    status,
};

/// Wait for the platform shutdown signal without starting any network work.
pub(crate) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
pub(crate) async fn up(config: PathBuf, dry_run: bool) -> Result<()> {
    let c = Config::load(&config)?;
    up_loaded(c, dry_run, shutdown_signal()).await
}

/// Run a validated daemon configuration until the supplied shutdown future
/// completes. Keeping the shutdown source injectable makes the full startup
/// and cleanup lifecycle testable without sending a process-wide signal.
async fn up_loaded(
    config: Config,
    dry_run: bool,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let mut c = config;
    let runtime = Runtime::new(c.clone())?;
    let dns = runtime.dns.clone();
    let supervisor = DaemonSupervisor::default();
    let fake_ip = c.fake_ip.clone().map(|config| {
        Arc::new(tinect::fake_ip::FakeIpRuntime::new(
            config,
            c.route_sets.clone(),
            c.domain_site_ids(),
            c.tun
                .addresses
                .iter()
                .map(|address| address.addr())
                .collect(),
            runtime.observability.clone(),
        ))
    });
    // Circuit workers use the immutable configuration snapshot owned by the
    // Runtime. Platform-resolved values such as an allocated TUN name belong
    // to NetworkResources and are intentionally not written back into this
    // snapshot.
    let runtime_config = runtime.config.clone();
    let has_egress_acl = !c.allowed_routes.is_empty() || !c.allowed_local_ports.is_empty();
    let plan = platform::network_plan(
        &c.tun,
        c.managed_routes,
        !c.allowed_routes.is_empty(),
        c.direct
            .as_ref()
            .map(|config| (config.fwmark, config.conntrack_zone)),
        c.post_up.as_ref().map(|commands| commands.as_slice()),
        !dry_run,
    )?;
    if dry_run {
        println!("network plan (dry run):");
        for command in plan {
            println!("  {}", command.join(" "))
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    // Contexts keep the `nft_healthy_set` keyword: startup tests assert the
    // Display contains it, so the inner error text is preserved inline.
    let mut healthy_set_manager = platform::HealthyRouteSetManager::open(
        c.nft_healthy_set_targets()
            .map_err(|error| anyhow::anyhow!("resolving nft_healthy_set targets: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("opening nft_healthy_set manager: {error}"))?;
    let socket = c.status_socket();
    let observability = runtime.observability.clone();
    let source_policy = dataplane::SourceAddressPolicy::from_config(&c, observability.clone());
    let state = runtime.state.clone();
    if let Some(bind) = c.runtime.metrics_listen {
        let metrics_state = state.clone();
        let metrics_cancellation = supervisor.token();
        supervisor
            .spawn(async move {
                if let Err(error) =
                    status::serve_metrics_until_cancelled(bind, metrics_state, metrics_cancellation)
                        .await
                {
                    tracing::warn!(error = %error, "metrics listener stopped");
                }
            })
            .await;
    }
    let topology = runtime.topology.clone();
    let control_plane = runtime.circuits.clone();
    let links = runtime.links.clone();
    // Load the node identity once and share it with every worker.  Workers
    // must never re-read the key file at runtime: if the file disappears or
    // is corrupted mid-flight, a worker would fail (or panic) and leave the
    // destination or LSA advertisement permanently unrecoverable.
    let daemon_key = Arc::new(c.load_identity().context("loading node identity key")?);
    let mut network_resources = NetworkResources::default();
    let circuit_router = match start_links(&c, &runtime, supervisor.clone(), &daemon_key).await {
        Ok((router, _listen_addr)) => router,
        Err(error) => {
            network_resources.rollback(&supervisor, &c).await;
            return Err(error);
        }
    };
    // Exact event-driven lease cleanup: the heap always sleeps only until
    // its nearest binding deadline (or a new earlier deadline notification),
    // never by periodically scanning all circuits.
    let lease_router = circuit_router.clone();
    let lease_sessions = control_plane.sessions.clone();
    let lease_return_flows = control_plane.return_flows.clone();
    let lease_circuit_dns = control_plane.circuit_dns.clone();
    let lease_cancel = supervisor.token();
    supervisor
        .spawn(async move {
            loop {
                let Some(deadline) = lease_router.next_lease_deadline() else {
                    tokio::select! {
                        _ = lease_cancel.cancelled() => return,
                        _ = lease_router.wait_for_lease_change() => continue,
                    }
                };
                tokio::select! {
                    _ = lease_cancel.cancelled() => return,
                    _ = lease_router.wait_for_lease_change() => continue,
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        for (link_instance, circuit_id) in lease_router.expire_due_bindings(std::time::Instant::now()).await {
                            lease_sessions.remove_circuit(link_instance, circuit_id).await;
                            lease_return_flows.remove_circuit(link_instance, circuit_id);
                            lease_circuit_dns.remove_circuit(link_instance, circuit_id);
                            tracing::info!(?circuit_id, link_instance, "circuit lease expired and state was reclaimed");
                        }
                    }
                }
            }
        })
        .await;
    state.write().await.status.node_identity = c.local_identity().ok();
    super::start_status_refresh(
        state.clone(),
        links.clone(),
        topology.clone(),
        observability.clone(),
        c.clone(),
        supervisor.clone(),
    )
    .await;
    super::start_topology_advertisements(
        &c,
        &daemon_key,
        links.clone(),
        topology.clone(),
        state.clone(),
        supervisor.clone(),
    )
    .await;
    start_circuit_reconciler(&runtime, daemon_key.clone(), supervisor.clone()).await;
    let has_routes = !c.route_imports().is_empty()
        || !c.domain_site_ids().is_empty()
        || !c.override_route_prefixes().is_empty()
        || c.direct
            .as_ref()
            .is_some_and(|direct| !direct.routes.is_empty());
    let accepts_transit = c
        .peers
        .values()
        .any(|peer| peer.allows_transit(c.allow_transit));
    // A transit-only relay must not create a competing TUN DATAGRAM reader.
    // A manually-pathed source still owns a TUN when it is an active dialer,
    // while route imports and exits always imply a local data plane.
    let owns_tun = c.tun.enabled
        && (has_routes
            || has_egress_acl
            || c.direct.is_some()
            || (!c.connect_to.is_empty() && c.peers.values().any(|peer| !peer.paths.is_empty()))
            || c.peers.values().all(|peer| peer.paths.is_empty()));
    let managed_route_ownership = network_resources.managed_overlay_routes();
    if owns_tun {
        // TUN lifetime belongs to the node, not to the first authenticated
        // peer.  A peer-to-peer node always listens; it may be started before
        // its neighbours and must become usable when they connect later.
        let mut tun_config = c.tun.clone();
        if has_routes {
            tun_config.mtu = initial_tun_mtu(&c);
        }
        let device = match platform::create_tun(&tun_config) {
            Ok(device) => device,
            Err(error) => {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!("creating TUN device: {error}"));
            }
        };
        let tun_name = match device.name() {
            Ok(name) => name,
            Err(error) => {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!("resolving TUN device name: {error}"));
            }
        };
        tun_config.name = tun_name.clone();
        if let Err(error) =
            platform::configure_tun_addresses(&tun_name, &tun_config.addresses).await
        {
            network_resources.rollback(&supervisor, &c).await;
            return Err(anyhow::anyhow!("configuring TUN addresses: {error}"));
        }
        // An empty name asks the TUN backend to allocate one. Persist the
        // actual kernel name before any route, firewall, hook, or shutdown
        // path uses the configuration, otherwise those operations target "".
        if c.tun.name != tun_name {
            c.tun.name = tun_name.clone();
        }
        network_resources.tun_name = Some(tun_name);
        network_resources.lifecycle_hooks_active = true;
        let mut active_managed_overlay_routes = HashSet::new();
        if has_routes && c.managed_routes {
            let underlay = collect_underlay_endpoints(&c, &dns).await;
            let prefixes = managed_overlay_prefixes(&c);
            match platform::install_overlay_routes(&c.tun.name, &prefixes, &underlay).await {
                Ok(ownership) => network_resources.underlay_routes = Some(ownership),
                Err(error) => {
                    network_resources.rollback(&supervisor, &c).await;
                    return Err(anyhow::anyhow!("installing overlay routes: {error}"));
                }
            }
            active_managed_overlay_routes = prefixes.into_iter().collect();
            *managed_route_ownership.write().await = active_managed_overlay_routes.clone();
        }
        let direct_egress = match c.direct.as_ref() {
            Some(config) => {
                match dataplane::DirectEgress::open(
                    config.dscp,
                    config.conntrack_zone,
                    config.fallback,
                ) {
                    Ok(egress) => Some(egress),
                    Err(error) => {
                        network_resources.rollback(&supervisor, &c).await;
                        return Err(anyhow::anyhow!("opening direct egress: {error}"));
                    }
                }
            }
            None => None,
        };
        let local_identity = daemon_key.clone();
        let egress = if has_egress_acl {
            let names = c
                .peers
                .iter()
                .map(|(name, peer)| (peer.public_key.clone(), name.clone()))
                .collect();
            Some(dataplane::EgressPolicy {
                names: Arc::new(names),
                allowed_routes: Arc::new(c.allowed_routes.clone()),
                allowed_local_ports: Arc::new(c.allowed_local_ports.clone()),
                local_addresses: Arc::new(c.tun.addresses.clone()),
                metrics: observability.clone(),
            })
        } else {
            None
        };
        if has_routes || has_egress_acl || c.direct.is_some() {
            let route_snapshot =
                build_route_snapshot(&c, &links, &topology, &control_plane.opens).await;
            #[cfg(target_os = "linux")]
            if let Some(manager) = healthy_set_manager.as_mut()
                && let Err(error) =
                    manager.reconcile(&healthy_route_prefixes(&route_snapshot, fake_ip.as_deref()))
            {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!(
                    "reconciling nft healthy-route set: {error}"
                ));
            }
            let router = dataplane::spawn_tun_router_secure(
                device,
                route_snapshot,
                links
                    .lock()
                    .expect("link registry lock")
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
                local_identity.clone(),
                dataplane::RouterEgress {
                    remote: egress,
                    source_policy: source_policy.clone(),
                    direct: direct_egress.clone(),
                    clamp_mss: c.tun.clamp_mss,
                    fake_ip: fake_ip.clone(),
                    return_flows: control_plane.return_flows.clone(),
                },
                observability.clone(),
                dataplane::InboundDispatch {
                    identity: local_identity.clone(),
                    authorizations: circuit_router.authorizations(),
                    relay_labels: circuit_router.relay_labels(),
                    sessions: control_plane.sessions.clone(),
                    cancellation: supervisor.token(),
                    circuit_opens: control_plane.opens.clone(),
                    circuit_router: circuit_router.clone(),
                    circuit_dns: control_plane.circuit_dns.clone(),
                },
                supervisor.clone(),
            );
            if let Some(service) = fake_ip.clone() {
                let (udp, tcp) = match service.bind().await {
                    Ok(listeners) => listeners,
                    Err(error) => {
                        network_resources.rollback(&supervisor, &c).await;
                        return Err(error.context("binding FakeIP DNS listener"));
                    }
                };
                let cancellation = supervisor.token();
                supervisor
                    .spawn(async move {
                        if let Err(error) = service.serve_bound(udp, tcp, cancellation).await {
                            tracing::error!(error = %error, "FakeIP DNS service stopped");
                        }
                    })
                    .await;
            }
            let ensure_context =
                CircuitReconcileContext::new(&runtime, daemon_key.clone(), supervisor.clone());
            let ensure_opens = ensure_context.circuit_opens.clone();
            let ensure_cancel = supervisor.token();
            let ensure_supervisor = supervisor.clone();
            supervisor
                .spawn(async move {
                    loop {
                        let destinations = tokio::select! {
                            _ = ensure_cancel.cancelled() => return,
                            destinations = ensure_opens.wait_for_ensure_requests() => destinations,
                        };
                        for destination in destinations {
                            let Some(worker_claim) = ensure_opens.claim_worker(&destination) else {
                                continue;
                            };
                            // Run each destination's ensure independently.
                            // open_configured_circuit is a long-lived worker
                            // (it only returns once the circuit is live or
                            // the destination is withdrawn), so a serial loop
                            // would let one unreachable destination starve
                            // every later recovery request.
                            let ensure_context = ensure_context.clone();
                            ensure_supervisor.spawn_background(async move {
                                if let Err(error) =
                                    open_configured_circuit(&ensure_context, &destination).await
                                {
                                    tracing::warn!(%destination, %error, "Circuit ensure request failed");
                                }
                                drop(worker_claim);
                            });
                        }
                    }
                })
                .await;
            let refresh_config = runtime_config.clone();
            let refresh_links = links.clone();
            let refresh_topology = topology.clone();
            let refresh_circuit_opens = control_plane.opens.clone();
            #[cfg(target_os = "linux")]
            let refresh_fake_ip = fake_ip.clone();
            let managed_route_tun = c.tun.name.clone();
            let managed_routes_enabled = c.managed_routes && has_routes;
            let managed_route_ownership = managed_route_ownership.clone();
            let initial_tun_mtu = initial_tun_mtu(&c);
            // Start at the conservative initial capacity, then allow the
            // route refresher to raise the interface as soon as every hop
            // reports its usable DATAGRAM limit.  The configured MTU remains
            // the user-supplied upper bound; clamping it to `initial_tun_mtu`
            // would permanently strand relay routes at 1097 bytes even when
            // QUICP can safely carry the larger configured packets.
            let configured_tun_mtu = c.tun.mtu;
            let fallback_tun = c.tun.name.clone();
            let refresh_cancel = supervisor.token();
            #[cfg(target_os = "linux")]
            let mut healthy_set_manager = healthy_set_manager.take();
            supervisor
                .spawn(async move {
                    // This set is the ownership ledger for the startup route
                    // snapshot; stale prefixes are deleted before additions.
                    let mut active_managed_overlay_routes = active_managed_overlay_routes;
                    let mut applied_tun_mtu = initial_tun_mtu;
                    loop {
                        let config = refresh_config.as_ref();
                        let snapshot = build_route_snapshot(
                            config,
                            &refresh_links,
                            &refresh_topology,
                            &refresh_circuit_opens,
                        )
                        .await;
                        #[cfg(target_os = "linux")]
                        if let Some(manager) = healthy_set_manager.as_mut()
                            && let Err(error) = manager.reconcile(&healthy_route_prefixes(&snapshot, refresh_fake_ip.as_deref()))
                        {
                            tracing::warn!(error = %error, "failed to synchronize healthy route nft set");
                        }
                        if managed_routes_enabled {
                            let desired_managed_routes = managed_overlay_prefixes(config)
                                .into_iter()
                                .collect::<HashSet<_>>();
                            if desired_managed_routes != active_managed_overlay_routes {
                                if let Err(error) = sync_managed_overlay_routes(
                                    &managed_route_tun,
                                    &mut active_managed_overlay_routes,
                                    desired_managed_routes,
                                )
                                .await
                                {
                                    tracing::warn!(error = %error, "failed to synchronize managed overlay routes");
                                } else {
                                    *managed_route_ownership.write().await =
                                        active_managed_overlay_routes.clone();
                                }
                            }
                        }
                        // Use live send budgets for the TUN MTU, not the
                        // snapshot-time `route.mtu` copies. A first-hop PMTU
                        // drop tightens `send_budget` immediately (and wakes
                        // this loop via the active generation); the snapshot
                        // copies only catch up after `build_route_snapshot`
                        // above. Using the live values keeps the kernel from
                        // emitting packets the new budget must drop, which is
                        // exactly the window where a fresh SYN would otherwise
                        // negotiate an MSS that no longer fits.
                        let route_mtu = snapshot.all_bindings().map(|route| {
                            u16::try_from(
                                route
                                    .send_budget
                                    .load(std::sync::atomic::Ordering::Acquire),
                            )
                            .unwrap_or(u16::MAX)
                        }).min();
                        // Keep the relay-safe MTU while topology is still
                        // converging. Raising back to the configured MTU when
                        // routes are temporarily absent would allow oversized
                        // GSO packets during reconnect and collapse QUIC cwnd.
                        let desired_tun_mtu = route_mtu
                            .map_or(initial_tun_mtu, |mtu| mtu.min(configured_tun_mtu));
                        #[cfg(target_os = "linux")]
                        let fake_ip_overhead = if snapshot.has_healthy_domain_binding() {
                            refresh_fake_ip
                                .as_ref()
                                .map_or(0, |runtime| runtime.max_envelope_len())
                        } else {
                            0
                        };
                        #[cfg(not(target_os = "linux"))]
                        let fake_ip_overhead = 0;
                        let desired_tun_mtu = desired_tun_mtu.saturating_sub(
                            u16::try_from(fake_ip_overhead).expect("FakeIP envelope fits in MTU"),
                        );
                        if desired_tun_mtu != applied_tun_mtu {
                            match platform::set_tun_mtu(&fallback_tun, desired_tun_mtu).await {
                                Ok(()) => applied_tun_mtu = desired_tun_mtu,
                                Err(error) => tracing::warn!(
                                    tun = %fallback_tun,
                                    mtu = desired_tun_mtu,
                                    error = %error,
                                    "failed to synchronize TUN MTU"
                                ),
                            }
                        }
                        router.replace_routes(snapshot).await;
                        let connected = refresh_links
                            .lock()
                            .expect("link registry lock")
                            .values()
                            .cloned()
                            .collect::<Vec<_>>();
                        for link in connected {
                            router.attach_link(link);
                        }
                        let generation = refresh_circuit_opens.active_generation();
                        tokio::select! {
                            _ = refresh_cancel.cancelled() => return,
                            _ = refresh_circuit_opens.wait_active_change(generation) => {}
                        }
                    }
                })
                .await;
        // A Link has exactly one QUIC DATAGRAM receiver.  A transit node's
        // relay worker owns that receiver once a circuit is installed, so it
        // must never also start the legacy plain TUN bridge.  Keep the TUN
        // itself for local addressing and diagnostics, but do not feed
        // circuit traffic through it.
        } else if !accepts_transit
            && let Some(link) = wait_for_any_link(
                &links,
                &control_plane.opens,
                std::time::Duration::from_secs(10),
            )
            .await
        {
            dataplane::spawn_tun_link(device, link, source_policy.clone(), supervisor.clone());
        } else if accepts_transit {
            tracing::info!(
                tun = %c.tun.name,
                "transit-capable node TUN is local-only; encrypted circuit traffic bypasses it"
            );
        } else {
            tracing::warn!(
                "TUN is ready but no authenticated peer is available for the un-routed data plane"
            );
        }
        if !c.allowed_routes.is_empty() {
            match platform::apply_exit_network(&c.tun, !c.allowed_routes.is_empty()) {
                Ok(network) => network_resources.exit_network = Some(network),
                Err(error) => {
                    network_resources.rollback(&supervisor, &c).await;
                    return Err(anyhow::anyhow!("applying exit network: {error}"));
                }
            }
        }
        match platform::apply_tun_input_firewall(&c.tun) {
            Ok(firewall) => network_resources.tun_input_firewall = Some(firewall),
            Err(error) => {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!("applying TUN input firewall: {error}"));
            }
        }
        match platform::apply_direct_firewall(&c.tun, c.direct.as_ref()) {
            Ok(firewall) => network_resources.direct_firewall = Some(firewall),
            Err(error) => {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!("applying direct firewall: {error}"));
            }
        }
        match platform::apply_direct_nat(&c.tun, c.direct.as_ref(), c.managed_routes) {
            Ok(nat) => network_resources.direct_nat = Some(nat),
            Err(error) => {
                network_resources.rollback(&supervisor, &c).await;
                return Err(anyhow::anyhow!("applying direct NAT: {error}"));
            }
        }
        if let Some(direct) = &direct_egress {
            direct.activate();
        }
        if let Some(commands) = &c.post_up
            && let Err(error) =
                platform::run_lifecycle_hooks(commands.as_slice(), &c.tun.name, "post_up")
        {
            if let Some(commands) = &c.pre_down {
                let _ = platform::run_lifecycle_hooks(commands.as_slice(), &c.tun.name, "pre_down");
            }
            network_resources.rollback(&supervisor, &c).await;
            return Err(anyhow::anyhow!("running post_up lifecycle hooks: {error}"));
        }
        tracing::info!(tun = %c.tun.name, "TUN attached; waiting peers and routes reconcile dynamically");
    }
    tracing::info!(node = %c.id, status_socket = %socket, listen = %c.listen, "daemon started");
    let status_state = state.clone();
    let status_socket = socket.clone();
    let status_cancellation = supervisor.token();
    supervisor
        .spawn(async move {
            if let Err(error) =
                status::serve_until_cancelled(&status_socket, status_state, status_cancellation)
                    .await
            {
                tracing::warn!(error = %error, "status socket stopped");
            }
        })
        .await;
    shutdown.await;
    let _ = std::fs::remove_file(&socket);
    let daemon_result: Result<()> = Ok(());
    {
        let mut daemon = state.write().await;
        daemon.status.shutting_down = true;
        daemon.status.supervised_tasks = supervisor.task_count();
    }
    // Closing Links first wakes protocol readers and prevents a still-open
    // connection from outliving the network resources that shutdown releases.
    let registered_links = links
        .lock()
        .expect("link registry lock")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for link in registered_links {
        link.close("daemon shutdown");
    }
    if let Err(error) = supervisor
        .shutdown(std::time::Duration::from_secs(
            c.runtime.shutdown_timeout_secs,
        ))
        .await
    {
        tracing::warn!(error = %error, "daemon shutdown timed out");
        state.write().await.status.last_shutdown_error = Some(error);
    }
    if network_resources.lifecycle_hooks_active
        && let Some(commands) = &c.pre_down
        && let Err(error) =
            platform::run_lifecycle_hooks(commands.as_slice(), &c.tun.name, "pre_down")
    {
        tracing::warn!(error = %error, "pre_down hook failed");
    }
    network_resources.cleanup().await;
    daemon_result?;
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use tinect::identity;

    /// Netlink answers follow the *calling thread's* network namespace, while
    /// `/sys/class/net` and `/proc/net` keep showing the test process's
    /// original namespace. Privileged tests therefore observe interfaces,
    /// MTUs, and routes through rtnetlink only.
    #[cfg(target_os = "linux")]
    async fn netlink_handle() -> rtnetlink::Handle {
        let (connection, handle, _) =
            rtnetlink::new_connection().expect("netlink connection inside the test namespace");
        tokio::spawn(connection);
        handle
    }

    /// Look up one link by name, returning its ifindex and MTU.
    #[cfg(target_os = "linux")]
    async fn link_index_and_mtu(
        handle: &rtnetlink::Handle,
        name: &str,
    ) -> Option<(u32, Option<u32>)> {
        use futures_util::TryStreamExt;
        use rtnetlink::packet_route::link::LinkAttribute;
        let mut links = handle.link().get().match_name(name.to_owned()).execute();
        let link = links.try_next().await.ok()??;
        let mtu = link
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Mtu(mtu) => Some(*mtu),
                _ => None,
            });
        Some((link.header.index, mtu))
    }

    /// Names of every non-loopback link in the test namespace.
    #[cfg(target_os = "linux")]
    async fn non_loopback_link_names(handle: &rtnetlink::Handle) -> Vec<String> {
        use futures_util::TryStreamExt;
        use rtnetlink::packet_route::link::LinkAttribute;
        let mut links = handle.link().get().execute();
        let mut names = Vec::new();
        while let Ok(Some(link)) = links.try_next().await {
            for attribute in &link.attributes {
                if let LinkAttribute::IfName(name) = attribute
                    && name.as_str() != "lo"
                {
                    names.push(name.clone());
                }
            }
        }
        names.sort_unstable();
        names
    }

    /// Whether the main routing table holds `prefix` via the given ifindex.
    #[cfg(target_os = "linux")]
    async fn main_table_route_via(
        handle: &rtnetlink::Handle,
        prefix: ipnet::IpNet,
        ifindex: u32,
    ) -> bool {
        use futures_util::TryStreamExt;
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
        let mut routes = handle
            .route()
            .get(rtnetlink::packet_route::route::RouteMessage::default())
            .execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.table != 254 {
                continue;
            }
            let mut destination = None;
            let mut output = None;
            for attribute in &route.attributes {
                match attribute {
                    RouteAttribute::Destination(RouteAddress::Inet(address)) => {
                        destination = ipnet::IpNet::new(
                            std::net::IpAddr::V4(*address),
                            route.header.destination_prefix_length,
                        )
                        .ok();
                    }
                    RouteAttribute::Destination(RouteAddress::Inet6(address)) => {
                        destination = ipnet::IpNet::new(
                            std::net::IpAddr::V6(*address),
                            route.header.destination_prefix_length,
                        )
                        .ok();
                    }
                    RouteAttribute::Oif(index) => output = Some(*index),
                    _ => {}
                }
            }
            if destination == Some(prefix) && output == Some(ifindex) {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    async fn assert_interface_absent(name: &str) {
        let handle = netlink_handle().await;
        assert!(
            link_index_and_mtu(&handle, name).await.is_none(),
            "test interface {name} leaked after startup failure"
        );
    }

    /// Minimal daemon configuration with a generated identity, an ephemeral
    /// loopback listener, and the status socket inside a temporary directory.
    fn identity_config(socket_path: &std::path::Path) -> Config {
        let key = identity::generate();
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
        config.runtime.status_socket = Some(socket_path.display().to_string());
        config
    }

    #[tokio::test]
    async fn disabled_tun_runs_startup_and_shutdown_without_network_devices() {
        let directory = tempfile::tempdir().unwrap();
        let key = identity::generate();
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
        config.tun.enabled = false;
        config.runtime.status_socket =
            Some(directory.path().join("daemon.sock").display().to_string());

        up_loaded(config, false, async {}).await.unwrap();
    }

    #[tokio::test]
    async fn disabled_tun_starts_optional_metrics_and_fake_ip_workers() {
        let directory = tempfile::tempdir().unwrap();
        let key = identity::generate();
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
        config.tun.enabled = false;
        config.runtime.status_socket =
            Some(directory.path().join("daemon.sock").display().to_string());
        config.runtime.metrics_listen = Some("127.0.0.1:0".parse().unwrap());
        config.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:0\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true",
            )
            .unwrap(),
        );

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(20)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn startup_reports_identity_and_listener_errors_before_network_setup() {
        let mut invalid_identity = crate::daemon::test_support::minimal_config();
        invalid_identity.identity_key = Some("not-a-private-key".into());
        invalid_identity.identity_key_path = None;
        invalid_identity.tun.enabled = false;
        assert!(up_loaded(invalid_identity, false, async {}).await.is_err());

        let mut invalid_listener = crate::daemon::test_support::minimal_config();
        invalid_listener.identity_key = Some(identity::encode_secret(&identity::generate()));
        invalid_listener.identity_key_path = None;
        invalid_listener.listen = "not-a-carrier://127.0.0.1:1".into();
        invalid_listener.tun.enabled = false;
        assert!(up_loaded(invalid_listener, false, async {}).await.is_err());
    }

    #[tokio::test]
    async fn up_dry_run_prints_the_network_plan_without_network_work() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:1\ntun: {name: tinea, addresses: [10.64.0.1/32]}\n",
        )
        .unwrap();
        up(config_path.clone(), true).await.unwrap();
        // A missing configuration file fails before any plan is built.
        assert!(
            up(directory.path().join("missing.yaml"), true)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tun_startup_rejects_missing_address_before_device_creation() {
        let key = identity::generate();
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
        config.tun.addresses.clear();
        assert!(up_loaded(config, false, async {}).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_tun_lifecycle_configures_and_cleans_up_transit_only_node() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let key = identity::generate();
        let peer_key = identity::generate();
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
        config.managed_routes = false;
        config.tun.name = "tinectcov".into();
        config.runtime.status_socket =
            Some(directory.path().join("daemon.sock").display().to_string());
        config.peers.insert(
            "relay".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&peer_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: Some(true),
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        );

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_secure_tun_lifecycle_starts_route_router_and_refreshers() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let key = identity::generate();
        let peer_key = identity::generate();
        let config_path = directory.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:0\ntun: {{name: tinectcv2, addresses: [10.64.0.1/32]}}\npeers:\n  exit:\n    public_key: {}\n    endpoints: []\n    allow_transit: true\n    routes:\n      - {{ip_cidr: 198.51.100.0/24, priority: 100}}\n",
                identity::encode_public(&peer_key.verifying_key())
            ),
        )
        .unwrap();
        let mut config = Config::load(&config_path).unwrap();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        config.managed_routes = true;
        config.direct = Some(tinect::config::DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 32123,
            routes: Vec::new(),
        });
        config.post_up = Some(vec!["true".into()].into());
        config.pre_down = Some(vec!["true".into()].into());
        config.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:0\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true",
            )
            .unwrap(),
        );
        config.runtime.status_socket =
            Some(directory.path().join("daemon.sock").display().to_string());

        let mut no_fake_config = config.clone();
        no_fake_config.fake_ip = None;
        no_fake_config.direct = None;
        no_fake_config.tun.name = "tinectcv3".into();
        no_fake_config.runtime.status_socket = Some(
            directory
                .path()
                .join("daemon-no-fake.sock")
                .display()
                .to_string(),
        );
        up_loaded(
            no_fake_config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(100)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn metrics_listener_conflict_is_logged_without_failing_startup() {
        let directory = tempfile::tempdir().unwrap();
        // Hold the port so the metrics worker's bind fails inside the task;
        // the failure must be logged without failing the daemon itself.
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.enabled = false;
        let bind = blocker.local_addr().unwrap();
        config.runtime.metrics_listen = Some(bind);
        let runtime = Runtime::new(config.clone()).unwrap();
        let error = status::serve_metrics_until_cancelled(
            bind,
            runtime.state.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
        drop(blocker);
    }

    #[tokio::test]
    async fn status_socket_refusal_is_logged_without_failing_startup() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("daemon.sock");
        // A pre-existing regular file makes the status server refuse the
        // path; the worker logs the error and the daemon keeps running.
        std::fs::write(&socket_path, "not a socket").unwrap();
        let mut config = identity_config(&socket_path);
        config.tun.enabled = false;
        let runtime = Runtime::new(config.clone()).unwrap();
        let error = status::serve_until_cancelled(
            &socket_path,
            runtime.state.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_nft_healthy_set_config_fails_before_network_setup() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.enabled = false;
        config.nft_healthy_set = Some(tinect::config::NftHealthySetConfig {
            prefix: Some("missing-separator".into()),
            ..Default::default()
        });

        let error = up_loaded(config, false, async {}).await.unwrap_err();
        assert!(error.to_string().contains("nft_healthy_set"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_nft_healthy_set_opens_and_releases_with_disabled_tun() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.enabled = false;
        config.nft_healthy_set = Some(tinect::config::NftHealthySetConfig {
            prefix: Some("tinectcov:healthy".into()),
            destroy_set: true,
            destroy_table: true,
            ..Default::default()
        });

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(20)),
        )
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_path_only_peer_does_not_own_tun() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let peer_key = identity::generate();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        // The TUN stays enabled, but a manually-pathed peer without local
        // routes, egress ACL, direct fallback, or dial targets means the
        // node must not claim the TUN data plane at all.
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&peer_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: vec![tinect::config::ConfiguredPath {
                    path: vec!["a".into(), "exit".into()],
                    override_routes: Vec::new(),
                    override_upstream_dns: None,
                }],
            },
        );

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_direct_fallback_rejects_zero_conntrack_zone_and_rolls_back() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tinectcvz".into();
        config.direct = Some(tinect::config::DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 0,
            routes: Vec::new(),
        });

        let error = up_loaded(config, false, async {}).await.unwrap_err();
        assert!(error.to_string().contains("conntrack zone"), "{error}");
        assert_interface_absent("tinectcvz").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_fake_ip_bind_conflict_rolls_back() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        // Hold the FakeIP listen port so the bind fails after the TUN and
        // the secure router were already started, exercising the rollback.
        let blocker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = blocker.local_addr().unwrap().port();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tinectcvf".into();
        config.direct = Some(tinect::config::DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 32126,
            routes: Vec::new(),
        });
        config.fake_ip = Some(
            serde_yaml::from_str(&format!(
                "listen: 127.0.0.1:{port}\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true"
            ))
            .unwrap(),
        );

        let error = up_loaded(config, false, async {}).await.unwrap_err();
        assert!(error.to_string().contains("FakeIP DNS listener"), "{error}");
        assert_interface_absent("tinectcvf").await;
        drop(blocker);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_post_up_failure_runs_pre_down_and_rolls_back() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tinectcvh".into();
        config.direct = Some(tinect::config::DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 32127,
            routes: Vec::new(),
        });
        // A failing post_up hook must attempt pre_down and then roll back
        // every network resource installed so far.
        config.post_up = Some(vec!["false".into()].into());
        config.pre_down = Some(
            vec![format!(
                "test -n \"$TINECT_TUN\" && touch {} && false",
                directory.path().join("pre-down-ran").display()
            )]
            .into(),
        );

        let error = up_loaded(config, false, async {}).await.unwrap_err();
        assert!(error.to_string().contains("post_up"), "{error}");
        assert!(directory.path().join("pre-down-ran").exists());
        assert_interface_absent("tinectcvh").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_exit_acl_without_ip_forwarding_rolls_back() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        // A fresh namespace has forwarding disabled, so the exit-network
        // preflight rejects the configuration after the TUN is up.
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tinectcve".into();
        config.allowed_routes.push(tinect::config::AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: Vec::new(),
            r#for: tinect::config::RouteSourceSelector::Keyword("any_known".into()),
        });

        let error = up_loaded(config, false, async {}).await.unwrap_err();
        assert!(
            error.to_string().contains("net.ipv4.ip_forward")
                || error.to_string().contains("net.ipv6.conf.all.forwarding"),
            "{error}"
        );
        assert_interface_absent("tinectcve").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_exit_lifecycle_logs_pre_down_failure_at_shutdown() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        // The forwarded-exit preflight reads per-namespace sysctls; enable
        // them only inside the isolated namespace so the host is untouched.
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tinectcvx".into();
        config.allowed_routes.push(tinect::config::AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: Vec::new(),
            r#for: tinect::config::RouteSourceSelector::Keyword("any_known".into()),
        });
        config.post_up = Some(vec!["true".into()].into());
        // A failing pre_down hook at shutdown must only be logged; the
        // daemon still shuts down cleanly and releases owned resources.
        config.pre_down = Some(vec!["false".into()].into());

        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
    }

    /// Query the management socket for one circuit's health; `None` means the
    /// socket is not up yet or the destination has no circuit entry.
    #[cfg(target_os = "linux")]
    async fn circuit_active_and_healthy(
        socket: &std::path::Path,
        destination: &str,
    ) -> Option<bool> {
        let bytes = status::request(socket, status::ManagementOpcode::Status)
            .await
            .ok()?;
        let status = status::decode_status(&bytes).ok()?;
        Some(status.circuits.iter().any(|circuit| {
            circuit.destination == destination && circuit.healthy && !circuit.active_path.is_empty()
        }))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_allocated_tun_name_direct_domain_route_and_healthy_set_lifecycle() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let key = identity::generate();
        let peer_key = identity::generate();
        std::fs::write(directory.path().join("domains.txt"), "target.test\n").unwrap();
        let post_up_record = directory.path().join("post-up-tun-name");
        let config_path = directory.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:0\ntun: {{name: \"\", addresses: [10.64.0.1/32]}}\nruntime:\n  status_socket: {}\nfake_ip:\n  listen: 127.0.0.1:15399\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\nnft_healthy_set:\n  prefix: tincovapp:healthy\n  destroy_set: true\n  destroy_table: true\ndirect:\n  fallback: false\n  dscp: 46\n  conntrack_zone: 32130\n  routes:\n    - {{site_set: ./domains.txt, priority: 100}}\npeers:\n  exit:\n    public_key: {}\n    endpoints: []\n    routes:\n      - {{ip_cidr: 198.51.100.0/24, priority: 100}}\npost_up:\n  - printf %s \"$TINECT_TUN\" > {}\npre_down:\n  - 'true'\n",
                directory.path().join("daemon.sock").display(),
                identity::encode_public(&peer_key.verifying_key()),
                post_up_record.display(),
            ),
        )
        .unwrap();
        let mut config = Config::load(&config_path).unwrap();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        // With no links there are no route bindings, so the refresh loop's
        // only MTU input is the initial capacity minus the FakeIP envelope
        // reserved for the healthy direct domain route.
        let expected_mtu = initial_tun_mtu(&config).saturating_sub(
            u16::try_from(tinect::fake_ip::max_fake_ip_envelope_len(true)).unwrap(),
        );

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let mut daemons = {
            let shutdown = shutdown.clone();
            vec![tokio::spawn(up_loaded(config, false, async move {
                shutdown.notified().await;
            }))]
        };

        // An empty configured name lets the kernel allocate the TUN name; the
        // daemon must persist it before hooks, routes, and firewalls use it.
        let netlink = netlink_handle().await;
        wait_daemon_condition(
            &mut daemons,
            || async { !non_loopback_link_names(&netlink).await.is_empty() },
            std::time::Duration::from_secs(10),
            "the daemon to create a kernel-named TUN device",
        )
        .await;
        let names = non_loopback_link_names(&netlink).await;
        let [tun_name] = names.as_slice() else {
            panic!("expected exactly one daemon TUN device, found {names:?}");
        };
        let tun_name = tun_name.clone();
        wait_daemon_condition(
            &mut daemons,
            || async { post_up_record.exists() },
            std::time::Duration::from_secs(10),
            "the post_up hook to run with the allocated TUN name",
        )
        .await;
        assert_eq!(
            std::fs::read_to_string(&post_up_record).unwrap(),
            tun_name,
            "post_up must observe the kernel-allocated TUN name"
        );
        // The configured overlay address is live on the namespace stack.
        std::net::UdpSocket::bind("10.64.0.1:0").unwrap();
        let tun_index = link_index_and_mtu(&netlink, &tun_name)
            .await
            .expect("the daemon TUN link exists")
            .0;
        wait_daemon_condition(
            &mut daemons,
            || async {
                main_table_route_via(&netlink, "198.51.100.0/24".parse().unwrap(), tun_index).await
            },
            std::time::Duration::from_secs(10),
            "managed overlay routes to point at the TUN device",
        )
        .await;
        let mtu_probe = tun_name.clone();
        wait_daemon_condition(
            &mut daemons,
            || async {
                link_index_and_mtu(&netlink, &mtu_probe).await
                    == Some((tun_index, Some(u32::from(expected_mtu))))
            },
            std::time::Duration::from_secs(15),
            "the route refresher to reserve the FakeIP envelope from the TUN MTU",
        )
        .await;
        // A packet toward the unreachable route import has no healthy
        // candidate: the dataplane rejects it and files a packet-driven
        // circuit ensure request for the configured destination.
        let sender = std::net::UdpSocket::bind("10.64.0.1:0").unwrap();
        for _ in 0..3 {
            sender.send_to(b"ensure", "198.51.100.1:9").unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        shutdown.notify_one();
        for daemon in daemons {
            daemon.await.unwrap().unwrap();
        }
        assert_interface_absent(&tun_name).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_two_node_circuits_drive_route_refresh_and_link_attach() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let key_a = identity::generate();
        let key_b = identity::generate();
        let port_a = unused_udp_port();
        let port_b = unused_udp_port();
        let socket_a = directory.path().join("a.sock");
        let socket_b = directory.path().join("b.sock");

        // One load helper per node keeps the two YAML documents explicit;
        // routes and path proofs must load through Config::load so site-set
        // interning and validation run exactly as in production.
        let load_node = |path: &std::path::Path, key: &ed25519_dalek::SigningKey| {
            let mut config = Config::load(path).unwrap();
            config.identity_key = Some(identity::encode_secret(key));
            config.identity_key_path = None;
            config
        };
        let path_a = directory.path().join("a.yaml");
        std::fs::write(
            &path_a,
            format!(
                "id: a\naccept_connections: true\nidentity_key_path: unused\nlisten: quic://127.0.0.1:{port_a}\ntun: {{name: tincova, addresses: [10.64.0.1/32]}}\nruntime:\n  status_socket: {}\nlink_health:\n  keepalive_secs: 1\npeers:\n  b:\n    public_key: {}\n    endpoints: [quic://127.0.0.1:{port_b}]\n    routes:\n      - {{ip_cidr: 10.64.0.2/32, priority: 100}}\n    paths:\n      - {{path: [a, b]}}\nconnect_to: [b]\n",
                socket_a.display(),
                identity::encode_public(&key_b.verifying_key()),
            ),
        )
        .unwrap();
        let config_a = load_node(&path_a, &key_a);
        let path_b = directory.path().join("b.yaml");
        std::fs::write(
            &path_b,
            format!(
                "id: b\naccept_connections: true\nidentity_key_path: unused\nlisten: quic://127.0.0.1:{port_b}\ntun: {{name: tincovb, addresses: [10.64.0.2/32]}}\nruntime:\n  status_socket: {}\nlink_health:\n  keepalive_secs: 1\npeers:\n  a:\n    public_key: {}\n    endpoints: [quic://127.0.0.1:{port_a}]\n    routes:\n      - {{ip_cidr: 10.64.0.1/32, priority: 100}}\n    paths:\n      - {{path: [b, a]}}\n",
                socket_b.display(),
                identity::encode_public(&key_a.verifying_key()),
            ),
        )
        .unwrap();
        let config_b = load_node(&path_b, &key_b);

        let shutdown_a = Arc::new(tokio::sync::Notify::new());
        let shutdown_b = Arc::new(tokio::sync::Notify::new());
        let mut daemons = vec![
            tokio::spawn(up_loaded(config_a, false, {
                let shutdown = shutdown_a.clone();
                async move {
                    shutdown.notified().await;
                }
            })),
            tokio::spawn(up_loaded(config_b, false, {
                let shutdown = shutdown_b.clone();
                async move {
                    shutdown.notified().await;
                }
            })),
        ];

        // A live signed circuit on each side gives the route refresher a real
        // binding with an MTU budget and a connected link to attach.
        wait_daemon_condition(
            &mut daemons,
            || async { circuit_active_and_healthy(&socket_a, "b").await == Some(true) },
            std::time::Duration::from_secs(30),
            "node a to hold a healthy circuit to b",
        )
        .await;
        wait_daemon_condition(
            &mut daemons,
            || async { circuit_active_and_healthy(&socket_b, "a").await == Some(true) },
            std::time::Duration::from_secs(30),
            "node b to hold a healthy circuit to a",
        )
        .await;
        let netlink = netlink_handle().await;
        for (tun_name, peer_prefix) in [("tincova", "10.64.0.2/32"), ("tincovb", "10.64.0.1/32")] {
            let (index, _) = link_index_and_mtu(&netlink, tun_name)
                .await
                .unwrap_or_else(|| panic!("daemon TUN {tun_name} must exist"));
            assert!(
                main_table_route_via(&netlink, peer_prefix.parse().unwrap(), index).await,
                "managed overlay route {peer_prefix} must point at {tun_name}"
            );
        }

        shutdown_a.notify_one();
        shutdown_b.notify_one();
        for daemon in daemons {
            daemon.await.unwrap().unwrap();
        }
        assert_interface_absent("tincova").await;
        assert_interface_absent("tincovb").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_unrouted_tun_bridges_over_first_authenticated_link() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let key_a = identity::generate();
        let key_b = identity::generate();
        let port_b = unused_udp_port();
        let socket_a = directory.path().join("a.sock");
        let socket_b = directory.path().join("b.sock");

        // Neither node imports routes or filters egress, so both take the
        // legacy un-routed plane: wait for the first authenticated link, then
        // bridge the local TUN onto it.
        let mut config_b = identity_config(&socket_b);
        config_b.id = "b".into();
        config_b.allow_transit = false;
        config_b.identity_key = Some(identity::encode_secret(&key_b));
        config_b.listen = format!("quic://127.0.0.1:{port_b}");
        config_b.tun.name = "tincovlb".into();
        config_b.tun.addresses = vec!["10.64.66.2/32".parse().unwrap()];
        config_b.peers.insert(
            "a".into(),
            peer_entry(identity::encode_public(&key_a.verifying_key()), Vec::new()),
        );

        let mut config_a = identity_config(&socket_a);
        config_a.allow_transit = false;
        config_a.identity_key = Some(identity::encode_secret(&key_a));
        config_a.tun.name = "tincovla".into();
        config_a.tun.addresses = vec!["10.64.66.1/32".parse().unwrap()];
        config_a.peers.insert(
            "b".into(),
            peer_entry(
                identity::encode_public(&key_b.verifying_key()),
                vec![format!("quic://127.0.0.1:{port_b}")],
            ),
        );
        // Outbound dialing is driven by connect_to; endpoints alone only
        // authorize the peer.
        config_a.connect_to = vec!["b".into()];

        let shutdown_a = Arc::new(tokio::sync::Notify::new());
        let shutdown_b = Arc::new(tokio::sync::Notify::new());
        let mut daemons = vec![
            tokio::spawn(up_loaded(config_a, false, {
                let shutdown = shutdown_a.clone();
                async move {
                    shutdown.notified().await;
                }
            })),
            tokio::spawn(up_loaded(config_b, false, {
                let shutdown = shutdown_b.clone();
                async move {
                    shutdown.notified().await;
                }
            })),
        ];

        wait_daemon_condition(
            &mut daemons,
            || async { peer_link_healthy(&socket_a, "b").await == Some(true) },
            std::time::Duration::from_secs(15),
            "node a to register a healthy link to b",
        )
        .await;
        wait_daemon_condition(
            &mut daemons,
            || async { peer_link_healthy(&socket_b, "a").await == Some(true) },
            std::time::Duration::from_secs(15),
            "node b to register a healthy link to a",
        )
        .await;
        let netlink = netlink_handle().await;
        assert!(link_index_and_mtu(&netlink, "tincovla").await.is_some());
        assert!(link_index_and_mtu(&netlink, "tincovlb").await.is_some());

        shutdown_a.notify_one();
        shutdown_b.notify_one();
        for daemon in daemons {
            daemon.await.unwrap().unwrap();
        }
        assert_interface_absent("tincovla").await;
        assert_interface_absent("tincovlb").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_unrouted_tun_without_peers_warns_after_bounded_link_wait() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        // No routes, egress rules, direct fallback, or peers: the node owns
        // the TUN, waits the bounded peer window, logs that the un-routed
        // data plane has no authenticated peer, and keeps serving.
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.allow_transit = false;
        config.tun.name = "tincovd".into();

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let mut daemons = {
            let shutdown = shutdown.clone();
            vec![tokio::spawn(up_loaded(config, false, async move {
                shutdown.notified().await;
            }))]
        };
        let netlink = netlink_handle().await;
        wait_daemon_condition(
            &mut daemons,
            || async { link_index_and_mtu(&netlink, "tincovd").await.is_some() },
            std::time::Duration::from_secs(10),
            "the daemon to create its TUN device before waiting for a peer",
        )
        .await;

        // The startup peer wait is bounded at ten seconds; the notify permit
        // is retained, so the daemon shuts down as soon as startup completes.
        shutdown.notify_one();
        for daemon in daemons {
            daemon.await.unwrap().unwrap();
        }
        assert_interface_absent("tincovd").await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_duplicate_tun_address_rolls_back_after_device_creation() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.name = "tincovdup".into();
        // The first address is assigned at device creation; re-adding it as a
        // secondary address fails with EEXIST after the TUN already exists,
        // exercising the startup rollback of the created device.
        config.tun.addresses = vec![
            "10.64.0.1/32".parse().unwrap(),
            "10.64.0.1/32".parse().unwrap(),
        ];

        assert!(up_loaded(config, false, async {}).await.is_err());
        assert_interface_absent("tincovdup").await;
    }

    /// Reserve a loopback UDP port that nothing listens on.
    fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn peer_entry(public_key: String, endpoints: Vec<String>) -> tinect::config::Peer {
        tinect::config::Peer {
            public_key,
            endpoints,
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: Vec::new(),
        }
    }

    async fn wait_until<F, Fut>(mut condition: F, timeout: std::time::Duration, description: &str)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = std::time::Instant::now() + timeout;
        while !condition().await {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Poll `condition` like `wait_until`, but surface a daemon's startup
    /// error immediately instead of reporting a bare timeout when the daemon
    /// task exits before the condition holds.
    #[cfg(target_os = "linux")]
    async fn wait_daemon_condition<F, Fut>(
        daemons: &mut [tokio::task::JoinHandle<Result<()>>],
        mut condition: F,
        timeout: std::time::Duration,
        description: &str,
    ) where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = std::time::Instant::now() + timeout;
        while !condition().await {
            if let Some(finished) = daemons.iter_mut().find(|daemon| daemon.is_finished()) {
                let outcome = finished.await.expect("daemon task panicked");
                panic!("daemon exited while waiting for {description}: {outcome:?}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Query the management socket for one peer's link health; `None` means
    /// the socket is not up yet or the peer has no link entry.
    async fn peer_link_healthy(socket: &std::path::Path, peer: &str) -> Option<bool> {
        let bytes = status::request(socket, status::ManagementOpcode::Status)
            .await
            .ok()?;
        status::decode_status(&bytes)
            .ok()?
            .links
            .into_iter()
            .find(|link| link.peer == peer)
            .map(|link| link.healthy)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_signal_resolves_on_sigterm() {
        // Registering a guard stream first installs Tokio's process-wide
        // SIGTERM handler, so the signals sent below are caught and broadcast
        // to every registered listener instead of killing the test process.
        let mut guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM guard");
        let waiter = tokio::spawn(shutdown_signal());
        tokio::pin!(waiter);
        // Resend until the waiter has registered its own stream and observes
        // the broadcast; the installed handler keeps every send harmless.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
            match tokio::time::timeout(std::time::Duration::from_millis(100), &mut waiter).await {
                Ok(result) => {
                    result.expect("shutdown_signal task panicked");
                    break;
                }
                Err(_) => assert!(
                    std::time::Instant::now() < deadline,
                    "shutdown_signal did not resolve on SIGTERM"
                ),
            }
        }
        // The guard was registered before the first send, so it must have
        // observed at least one broadcast, proving the handler caught the
        // signal rather than the process dying by default disposition.
        tokio::time::timeout(std::time::Duration::from_secs(1), guard.recv())
            .await
            .expect("guard missed the SIGTERM broadcast")
            .expect("guard stream closed unexpectedly");
    }

    #[tokio::test]
    async fn shutdown_join_timeout_is_logged_without_failing_the_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = identity_config(&directory.path().join("daemon.sock"));
        config.tun.enabled = false;
        // A zero join budget makes the supervisor's shutdown wait time out
        // while workers are still winding down; the overrun must be logged
        // and recorded without failing the daemon's shutdown path.
        config.runtime.shutdown_timeout_secs = 0;
        up_loaded(
            config,
            false,
            tokio::time::sleep(std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_registered_links_before_joining_tasks() {
        let directory = tempfile::tempdir().unwrap();
        let key_a = identity::generate();
        let key_b = identity::generate();
        let port_b = unused_udp_port();

        let mut config_b = identity_config(&directory.path().join("b.sock"));
        config_b.id = "b".into();
        config_b.identity_key = Some(identity::encode_secret(&key_b));
        config_b.tun.enabled = false;
        config_b.listen = format!("quic://127.0.0.1:{port_b}");
        config_b.peers.insert(
            "a".into(),
            peer_entry(identity::encode_public(&key_a.verifying_key()), Vec::new()),
        );

        let mut config_a = identity_config(&directory.path().join("a.sock"));
        config_a.id = "a".into();
        config_a.identity_key = Some(identity::encode_secret(&key_a));
        config_a.tun.enabled = false;
        config_a.peers.insert(
            "b".into(),
            peer_entry(
                identity::encode_public(&key_b.verifying_key()),
                vec![format!("quic://127.0.0.1:{port_b}")],
            ),
        );
        config_a.connect_to = vec!["b".into()];

        let socket_a = directory.path().join("a.sock");
        let socket_b = directory.path().join("b.sock");
        let shutdown_a = Arc::new(tokio::sync::Notify::new());
        let shutdown_b = Arc::new(tokio::sync::Notify::new());
        let daemon_a = {
            let shutdown = shutdown_a.clone();
            tokio::spawn(up_loaded(config_a, false, async move {
                shutdown.notified().await;
            }))
        };
        let daemon_b = {
            let shutdown = shutdown_b.clone();
            tokio::spawn(up_loaded(config_b, false, async move {
                shutdown.notified().await;
            }))
        };

        // Both sides must register an authenticated, healthy link first so
        // the shutdown below has a real Link to close.
        wait_until(
            || async { peer_link_healthy(&socket_a, "b").await == Some(true) },
            std::time::Duration::from_secs(15),
            "node a to register a healthy link to b",
        )
        .await;
        wait_until(
            || async { peer_link_healthy(&socket_b, "a").await == Some(true) },
            std::time::Duration::from_secs(15),
            "node b to register a healthy link to a",
        )
        .await;

        shutdown_a.notify_one();
        daemon_a.await.unwrap().unwrap();
        // Closing registered links during shutdown must be observable by the
        // peer: b's link to a goes away or turns unhealthy without waiting
        // for keepalive expiry.
        wait_until(
            || async { peer_link_healthy(&socket_b, "a").await != Some(true) },
            std::time::Duration::from_secs(15),
            "node b to observe the closed link to a",
        )
        .await;

        shutdown_b.notify_one();
        daemon_b.await.unwrap().unwrap();
    }
}
