# RFC-0020: Linux netlink network control without ip

- Number: RFC-0020
- Status: Implemented
- Title: Linux netlink network control without ip
- Created: 2026-08-02
- Last updated: 2026-08-02

## Background and Problem

Tinect's Linux platform layer has direct overlay routing via `rtnetlink` and management of nftables
via `libnftnl`/`libmnl`. Historically, policy routing fallback required copying the default route
and installing rules, resulting in dependence on additional routing status at runtime; currently
local-route-fallback has been changed to TUN post-raw-IP socket, and this type of routing table
operation is no longer performed.

## Goals and Non-goals

Target:

1. The `ip` executable file is no longer launched when the Linux service is running;
2. Maintain overlay routing and TUN MTU adjustment semantics; local-route-fallback does not write
   any routing state;
3. Return structured errors via netlink and preserve conflict detection, rollback, and cleanup
   boundaries for Tinect resources;
4. No changes to macOS' `route`/`ifconfig` implementation.

Non-goals:

- No changes to configuration fields, route priorities, policy rule priorities, or NAT semantics;
- Do not take over the host that already has policy rules, routing tables or default routes;
- Do not remove the use of `ip` in test scripts and diagnostic documents; these are test/operation
  and maintenance tool dependencies, not daemon runtime dependencies;
- IP forwarding on Linux is not automatically enabled.

## the term

This RFC no longer defines local-route-fallback's dedicated routing tables, policy rules, or default
route snapshots; the fallback egress is determined by the raw-IP socket's optional interface binding
and the kernel default egress.

## design

### Unified netlink entrance

The Linux platform layer uses `rtnetlink::new_connection()` to create the route-netlink connection
and drives the connection in the Tokio task. All requests wait for kernel ACK; errors are translated
to `PlatformError::Command` to preserve the existing platform error interface.

### local-route-fallback

After the target packet enters TUN, the platform layer uses raw-IP socket to send it. Set
`SO_BINDTODEVICE` when configuring the interface. If not configured, the interface will not be bound
and the kernel will select the default egress. When configuring `fwmark`, set `SO_MARK` regardless
of whether the interface is bound or not. This path does not create, delete, or modify routes,
rules, or routing tables.

### TUN MTU

`ip link set dev <tun> mtu <value>` instead queries the interface index through link netlink, and
then sends `RTM_NEWLINK` request with `LinkAttribute::Mtu`. MTU changes still only occur when the
valid path capacity changes, and are still responsible for the `platform` layer.

### Lifecycle and cleanup

local-route-fallback does not own any policy rules or fallback tables, so startup, failure rollback,
and stop do not perform route status cleanup for this feature. The existing resource life cycles of
overlay routing and TUN MTU remain unchanged.

## Security and Compatibility impact

- No changes to any network packets, protocol frames, or encryption semantics.
- local-route-fallback does not operate any policy routing table or rules; overlay routing still
  only operates resources derived from Tinect and verified to be unoccupied.
- Eliminate the risk of misjudgment caused by `ip rule show` text inclusion matching and avoid the
  risk of shell/PATH hijacking.
- Linux deployments no longer require `iproute2` to provide the `ip` executable; the kernel must
  still support `NETLINK_ROUTE`, and services still require the original `CAP_NET_ADMIN`
  permissions.
- `ip` can still appear in real network integration tests, diagnostic commands, and RFC
  troubleshooting examples and is not a daemon runtime dependency.

## Migration and deployment

There is no need to modify the configuration after upgrading the Linux service. After removing the
`ip` executable, the default overlay route, egress NAT, TUN INPUT firewall, local-route-fallback,
and dynamic TUN MTU paths should continue to be available; real integration test scripts can use
`iproute2` to create namespaces, veths, and check network status; the daemon does not rely on this
command line tool when running.

## Testing and Acceptance

- `rg 'Command::new\("ip"\)|run_checked\("ip"' src` No results;
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  passed;
- Unit tests cover overlay routing and the netlink construct of TUN MTU; local-route-fallback
  platform tests cover `SO_MARK` of raw-IP socket;
- The Linux namespace integration test covers the specified interface and default exit path of
  local-route-fallback, and compares the routing table and rules before and after the fallback to
  prove that this function does not write the routing status;
- In a Linux environment that does not have the `ip` executable file but has the necessary dynamic
  libraries and kernel capabilities, the daemon can complete the TUN, routing, policy rules, NAT,
  and firewall life cycles.

## Open Questions

none.

## Implementation Notes

Implementation is at `src/platform.rs`: Linux overlay routing and TUN MTU are done via `rtnetlink`,
local-route-fallback is done via raw-IP socket, `ip` executable calls are not preserved. Linux
targets passed `cargo check`, Strict Clippy and `cargo test --all-features`; Structured Rules/Route
single test added `platform::tests`. The real namespace integration test still uses the `ip` tool of
the test script itself and has not been removed as a daemon runtime dependency.
