# Tinect

Tinect is a policy-driven Layer 3 overlay network with static configuration. It separates
**routing** (which egress handles a destination), **paths** (the peers traffic traverses), and
**circuits** (forwarding state installed along a path).

Carrier configuration supports `quic://`, `quicfull://`, `quic-faketcp://`, and
`quicfull-faketcp://`. The `quic://` and `quic-faketcp://` carriers use the bare Physical data
plane. The listener and each peer endpoint can select a carrier independently; the legacy
`quicp://` scheme is rejected. Physical v2 encrypts Circuit metadata at each hop, while relays
forward the end-to-end ciphertext unchanged and authenticate it as Physical AAD. If a receiver
encounters an unknown session or relay label, it sends a signed `CircuitBroken` message back along
the original path. The source then revokes and rebuilds the Circuit. If the feedback is lost, the
long lease, authenticated DATA refresh, and bounded renewal grace provide independent recovery.

The current version implements configuration validation, identity keys, ACLs, explicit Circuit
verification, per-packet routing, health tracking, direct fallback, a Unix status socket, QUIC peer
authentication, multi-hop Circuit control, TUN frame forwarding, egress NAT and filtering, and
end-to-end ChaCha20-Poly1305 encryption with an ephemeral X25519 key. `up` applies the network
configuration by default. When the local data plane is enabled, it creates a TUN device and
therefore requires root privileges. A relay-only node can set `tun.enabled: false` to avoid creating
a TUN device or changing local network settings.

## Quick start

```sh
cargo run -- keygen --output node.key
cargo run -- pubkey --key node.key
cp examples/client.yaml node.yaml
cargo run -- check node.yaml
cargo run -- routes node.yaml
sudo cargo run -- up node.yaml
cargo run -- --version
```

Before connecting to other nodes, please edit `node.yaml` to add peer and route. The example
configuration uses `identity_key_path: ./node.key`, so the generated private key should be placed in
the same directory as the copied configuration.

`tinect --version` will display the Cargo package version and Git short hash at build time, such as
`tinect 1.10.100 (git abc1234)`. When the release workflow builds a tag that conforms to the
`vnumber.number.number` format (for example, `v1.10.100`), it will temporarily set the version of
the root `Cargo.toml` to the version without the `v` prefix, so the version in the release binary
and container is consistent with the tag; other builds continue to use the version in the repository.
If the build environment has no Git repository or Git information cannot be read, the hash is
displayed as `unknown`; this does not affect building or running the program.

## Nix

The repository provides flake packages that can be built or run directly:

```sh
nix build github:cross-io/tinect
nix run github:cross-io/tinect -- --help
```

Other flakes can use this repository as an input and add the package through
`inputs.tinect.packages.${system}.default` (or equivalent `tinect`).

`up` applies network changes, runs continuously, and provides a local-only status interface at
`/run/tinect/<node-id>.sock` on Linux (`/var/run/tinect/<node-id>.sock` on macOS, both can be
overridden by `runtime.status_socket`). It requires root privileges; to review only the plan, use
`tinect up <config> --dry-run`. Another terminal can run `tinect status` (automatically discovered
when there is only one daemon in the default directory), `tinect status <config>`, `tinect status
--node <node-id>` or ` tinect status --socket <path>` to query it; sending ` Ctrl-C` will cancel the
supervised task and clean up network resources; `runtime.shutdown_timeout_secs` can set the upper
limit for waiting for task exit (default 10 seconds, range 1..=60).

`status` will return Link health/failure reason, current Circuit path, number of flows, number of
known topology nodes and topology generation, as well as the number of supervised tasks, whether it
is being shut down and recent shutdown errors; each connected Link also contains QUIC measured
transceiver packets/bytes, RTT, packet loss count/proportion, and current path MTU. Circuit also
exposes the preferred path and `Stable`, `MigrationPending`, `MigrationOverdue` migration status,
start time and recent failure reason. Each physical QUIC Link uses DPLPMTUD to independently detect
the PMTU and write the unidirectional DATAGRAM capacity into the signed topology announcement; the
multi-hop path takes the minimum capacity of all edges. `routes` returns static candidate exits and
priorities.

If `runtime.metrics_listen` is set (only binding `127.0.0.1` or `::1` is allowed), the daemon will
expose Prometheus text indicators at `GET /metrics`, including the number of healthy Link/Circuit,
the number of flows, and the topology generation.

You can use `tinect topology <config>`, `tinect topology --node <node-id>` or `tinect topology
--socket <path>` to export the Graphviz DOT topology at runtime. ` status `, ` routes `, ` topology` and
`pcap` all support single-daemon auto-discovery when the target is omitted, profile, `--socket
PATH `, `--node ID `; ` status ` and ` routes ` can also return a static preview from a configuration file when the daemon is not running. If there are multiple daemons in the default directory, `--node` or
`--socket` must be used instead. If `runtime.pcap_buffer_packets` is set explicitly, `tinect pcap
<config> --output traffic.pcap` exports the most recently decrypted inner IP packet (DLT_RAW, which
can be opened by Wireshark/tcpdump). PCAP contains sensitive payloads and is closed by default. The
status socket is only allowed to be read by the daemon owner.

The configuration remains unchanged after the daemon is started; modifying any configuration field
requires restarting the service. `tinect reload` is no longer provided to avoid partially updated
runtime status for paths, ACLs, and network resources.

For a direct two-node connection, configure each node as a peer of the other, set `connect_to` on
at least one node, configure the opposite TUN addresses, and add a peer-level `paths` entry (for
example, `peers.b.paths: [{path: [a, b]}]`). For a three-node `a -> relay -> exit` setup, configure
`{path: [a, relay, exit]}` under `peers.exit.paths` on `a`, and
`peers.exit.paths: [{path: [relay, exit]}]` on the relay to constrain forwarded traffic. Use
`override_routes` to adjust route priorities for an active path. To restrict which peers may use the
relay, set its top-level `allow_transit` default or override it with `peers.a.allow_transit`. On the
exit, configure `allowed_routes` and `allowed_local_ports`; on `a`, declare the destination prefixes
to send to the exit under `peers.exit.routes`. See [Configuration reference](config.md) for all
fields and copyable YAML examples.

Before running `up` as root on Linux, use `--dry-run` to review planned network changes. Linux uses
rtnetlink for overlay routes outside the local TUN subnet and `libnftnl`/`libmnl` for egress NAT.
Routes within the TUN subnet affect Tinect's internal routing and do not replace kernel-connected
routes. Before adding prefixes that could override the default route, Tinect creates underlay host
routes only for peer endpoints without a more specific route. It tracks these routes and removes
them at shutdown; existing administrator-managed routes are left unchanged. Set `managed_routes: false`
to leave system routes unmanaged while still using TUN and egress selection with external policy
routing. On macOS, Tinect uses `utun`, `route`, and a dedicated `com.tinect` PF anchor managed by
`pfctl-rs`. Shutdown removes only routes, PF/nft tables, and status sockets created by Tinect.

After `up` starts, the daemon waits for authenticated peers. By default, it establishes the
lowest-cost Circuit to each egress using the signed link-state topology, which advertises public-key
fingerprints and directional user-packet capacity. Use `paths` to override an egress's primary and
backup paths. Topology snapshots, deltas, and TTL-based lease renewals travel over the reliable
control stream. A Link is used as a topology edge only after its Snapshot is acknowledged. To open a
Circuit, the source negotiates ECDH in a reliable, signed OPEN message and creates a 128-bit
CircuitId from a random 64-bit prefix and a monotonic 64-bit counter. The CircuitId indexes the
forwarding and session state. DATA is sent only after the egress confirms installation.

Each TUN packet is routed by longest-prefix match, egress priority, and current health. Routes are
not pinned to a five-tuple, so traffic can return to a restored higher-priority egress on the next
packet. `direct.routes` lets the local egress compete at the same priority as peer routes (overlay
routes win ties). `direct.fallback: true` makes the local egress the last candidate when all matching
peers are unavailable. When `nft_healthy_set` is configured, Tinect updates healthy peer and direct
prefixes in one netlink batch per address family. The administrator's nft rules mark packets that
match the set and direct them to the TUN. Tinect marks locally reinjected packets with DSCP so they
can be handled by the local default egress. With `direct.fwmark`, Tinect also installs Linux
prerouting rules through `libnftnl`/`libmnl` to mark reinjected packets and clear their DSCP value.
The mark is reserved for direct fallback; Tinect drops marked packets that would loop back into its
own TUN.

Before reinjection, Tinect uses ctnetlink to delete the first-pass conntrack entry from the default
zone, then assigns the reinjected packet to the configured exclusive `conntrack_zone`. This avoids
`notrack` and leaves ordinary overlay conntrack state unchanged. When `managed_routes` is enabled,
Tinect also installs POSTROUTING masquerade for reinjected packets, after normal srcnat rules so
administrator-managed SNAT/masquerade rules retain priority. Each DATAGRAM is protected by per-Link
AEAD with direction, identity, sequence numbers, and replay protection. Relays unwrap and re-encapsulate
only this outer layer; the end-to-end ciphertext associated with the CircuitId is forwarded
unchanged. Idle physical links send authenticated stateless keepalives, while regular data suppresses
extra keepalives. Only the final egress decrypts traffic and applies routing, egress ACLs, and NAT.
Local outbound admission prioritizes control streams while keeping D0/D1/D2 queues bounded and
fair; this does not guarantee wire-level send order.

QUIC redial timing follows `link_health.reconnect_interval_secs` (default 2 seconds). Repeated
failures use exponential backoff capped at 5 seconds, and each dial attempt (DNS, QUIC, and identity
handshake) lasts at most 5 seconds. Closed Links are removed before dialing resumes. `tun.clamp_mss`
is enabled by default and clamps TCP SYN MSS for IPv4, IPv6, and common IPv6 extension headers.
The first release does not include TCP/WebSocket fallback or single-stream multipath.

## Security boundary

- The node identity is the Ed25519 private key; it can be provided through the `IDENTITY_KEY`
  environment variable, the top-level `identity_key` inline Base64 private key, or the top-level
  `identity_key_path` private key file. The priority is environment variable, inline
  configuration, and file path. At least one of the three is provided; when the environment
  variable exists, it will override the identity source in the configuration.
- Use `tinect pubkey --key node.key` to export the Base64 public key from the private key file; if
  the private key is already in the configuration or environment variable, use `tinect pubkey
  --secret "$IDENTITY_KEY"`. This command only outputs the public key, which can be directly
  filled in the peer's `public_key`. Note that `--secret` will expose the private key in the shell
  history and process list. The `--key` file format is preferred.
- The peers in the configuration are a static allowlist and unknown peers will be rejected in the
  QUIC application handshake.
- `accept_connections` is allowed by default, `allow_transit` is denied by default, and
  `peers.<name>` can be overridden respectively; any traffic bearing from unknown sources must
  also be explicitly enabled by `allow_relay: true` of the source peer; when `allowed_local_ports`
  is not written, only known sources are allowed to access all ports of the machine.
- `bind_addresses` and `peers.<name>.routes[].bind` can declare the ownership of the inner source
  address; when no binding is hit, the source peer is not restricted, and after a hit, only the
  bound peer identity is allowed. The relay does not decrypt or perform source address checking.
- On Linux, the top-level `fwmark` sets `SO_MARK` on Tinect's QUIC carrier sockets. `direct.fwmark`
  marks packets reinjected from TUN for native egress through the host's default route. These marks
  have different meanings, and both can be used with `ip rule`.
- The OPEN of each Circuit carries the temporary X25519 public key signed by source Ed25519, and
  derives the ChaCha20-Poly1305 DATA key accordingly; the receiver will reject replay frames on
  the same Circuit. An independent security audit is still recommended before production
  deployment.

See [Configuration Description](config.md) and [Example Configuration](../examples/client.yaml).

## Datagram FEC

Tinect enables adaptive datagram FEC on each physical link. Configuring `repair_rate` or
`connect_to` object with this field can set the upper limit of repair datagrams/source datagram; the
default value `0` means off. When turned off, Forward packet format and capacity remain completely
unchanged.

When enabled, FEC only protects the datagram on the current physical link; the multi-hop relay will
be independently encoded at each hop, and the end-to-end payload is still protected by the source
node and egress node. The user IP capacity of the FEC Link will be 16 bytes less than the normal
Link to accommodate the worst-case repair packets, and the MSS clamp and path MTU will use this
capacity. Capacity-related TUN, LSA, and OPEN values   are interpreted in terms of full user IP
packet bytes; the carrier's QUIC, bare UDP, fake-TCP, and Physical overhead are handled by the
Link boundary, as detailed in [RFC-0037](specs/RFC-0037-user-ip-capacity-and-tun-mtu-semantics.md).

Optional FakeIP domain routing, mixed domain/CIDR `site_set` rules, and routing based on ports or
ICMP identifiers are described in [RFC-0033](specs/RFC-0033-fake-ip-and-route-sets.md) and
RFC-0035. DNS traffic for a configured domain follows the same priority rules as healthy peers and
`direct.routes`, reusing the last successful egress first. `allowed_routes` authorizes the remote
upstream, while `direct.fallback` controls whether DNS can use the local resolver when all peers are
unavailable. IP-only `site_set` rules can be used without FakeIP. See [Architecture](architecture.md)
for module dependencies and layering, and [Protocol](protocol.md) for wire messages, control flows,
and known protocol limitations.

## Logging

The daemon uses a structured `tracing` log with the default level of `info`. Each line contains
time, level, module and context fields (such as `peer`, `destination`, `path`, `error`). Use
environment variables to adjust the verbosity:

```sh
RUST_LOG=tinect=debug sudo ./target/release/tinect up node.yaml
```

Commonly used levels are `tinect=info` (life cycle and status changes), `tinect=debug` (path/control
plane details) and `tinect=trace` (only used for short-term troubleshooting). The service manager
should collect stderr to journald or corresponding logging system.

The systemd unit for Linux and the launchd template for macOS are located in
[packaging](../packaging). Please adjust according to the actual binary and configuration paths
before installation.
