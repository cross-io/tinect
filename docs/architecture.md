# Architecture and layering

This document describes Tinect's current module boundaries. Recent refactoring keeps the wire
format, configuration, security semantics, and network resource ownership unchanged while moving
existing responsibilities into smaller modules connected by explicit interfaces.

## Current implementation boundaries

```text
main (CLI + startup orchestration)
  -> daemon::application::up
     -> Runtime + DaemonSupervisor
├─ daemon::support (time, identity, path, endpoint, and Link-tag helpers)
        ├─ link_lifecycle / control_handler / topology_sync
        │    └─ carrier::Link
│ ├─ QUIC stream/datagram or bare Physical underlay
        │       ├─ PhysicalSession, PMTU, FEC, priority admission
│ └─ platform::quicp (only fake-TCP raw socket)
        ├─ circuit_reconciler / path_resolution / route_snapshot
        │    └─ config,topology,routing,reconcile,circuit
│ └─ LinkHandle (exposes only the minimal Link capabilities through a trait object)
        ├─ dataplane
        │    ├─ TUN, packet inspection, MSS clamp, route snapshot
│ ├─ relay (transparent forwarding and feedback)
        │    ├─ E2E DATA, Circuit DNS, FakeIP, direct fallback
        │    └─ platform::TUN / routes / nft / ctnetlink
        └─ status / observability
```

The "dependency direction" here is the responsibility direction, not every Rust `use` is strictly
one-way. Physical reception, link lifecycle, and platform capabilities still use concrete
implementations; Circuit's outgoing binding, Router, and relay only hold `Arc<dyn LinkHandle>`, so
no Quinn, raw socket, FEC, or PMTU details are read.

### Module responsibilities

- `config`: Deserializes and statically validates configuration, then loads route-set files. It may
  read files in the configuration directory, but it does not start network tasks, create a TUN
  device, or change routes or firewall rules. The loaded configuration is immutable; route sets are
  referenced by `SetId` and a shared immutable index.
- `identity`, `crypto`, `wire`, `physical`, `mtu`, `fec`, `priority`, `reconcile`: Provide identity
  and encoding, end-to-end and hop-by-hop encryption, capacity calculations, FEC, send admission,
  and declarative reconciliation primitives. `physical` defines the Physical envelope but opens no
  sockets. `reconcile` owns no runtime tasks.
- `policy`, `routing`, `topology`: Make policy and path-selection decisions. `policy` and `routing`
  are mostly pure decision modules. `topology` signs LSAs, checks replay and expiration, calculates
  capacity, and finds paths subject to constraints. It performs no host network I/O, though it
  currently uses `tokio::sync::Notify` to wake consumers when topology changes. Topology advertises
  node and directed-link costs and user-packet capacity, but not egress prefixes.
- `circuit`: Verifies OPEN, enforces transit and relay admission, manages hop-by-hop bindings and
  relay labels, and handles Circuit leases, shutdown, and feedback. It is carrier-independent. Its
  outgoing bindings, Router, and relay use `link::LinkRef` and `LinkDirectory` to find a Link by
  instance or identity and to check health before sending control or forwarding messages. The
  daemon and carrier still manage physical Link lifecycles. The source's `CircuitOpenManager`, exit
  session, return-flow table, and Circuit DNS remain separate components assembled by the
  `runtime::CircuitRuntime` facade.
- `carrier`: Provides authenticated QUIC Links and a bearer abstraction. `carrier::error` centralizes
  transport errors, while `carrier::Link` adapts the transport to `LinkHandle`. It handles
  Hello/HelloAck, QUIC streams and DATAGRAMs, bare-UDP receive IDs, fake-TCP adaptation,
  `PhysicalSession`, PMTU, FEC, Link health, and priority admission. Ordinary QUIC sockets belong to
  the carrier; fake-TCP's raw socket and RST guard are implemented by `platform`. Each Link has one
  consumer for its Forward receive queue; that consumer may be a simple TUN bridge, the secure
  dataplane, or a relay worker.
- `dataplane`: Reads from and writes to TUN, parses IP packets, clamps MSS against the live path
  budget, segments oversized TCP GSO packets, rate-limits ICMP Packet Too Big responses for
  over-budget packets, selects routes per packet, encrypts and decrypts end-to-end DATA, and applies
  egress ACLs. It also handles Circuit DNS, FakeIP, and Linux direct fallback. All decrypted traffic
  sent to a remote egress must pass `EgressPolicy::authorize()`. Native direct is the explicit local
  egress exception and does not use the remote egress ACL.
- `route_sets`: Builds immutable mixed domain/CIDR SiteSets at configuration load. It deduplicates
  by canonical path and content hash. Routes, direct candidates, and path overrides retain a `SetId`
  and shared route specification rather than reparsing files on the packet-processing path.
- `platform`: Adapts privileged host networking operations. Linux configures TUN, MTU, and overlay
  and underlay routes through rtnetlink; nftables, NAT, TUN firewall rules, and ctnetlink use
  `libnftnl`/`libmnl`; fake-TCP uses raw sockets. macOS uses `route`, `ifconfig`, and `pfctl-rs`.
  Ordinary QUIC, FakeIP DNS, and status sockets belong to `carrier`, `fake_ip`, and `status`,
  respectively. Runtime setup does not depend on the `ip` or `nft` commands. Lifecycle hooks are an
  explicit trusted-shell exception.
- `runtime`, `daemon`: Compose and supervise the application. `Runtime` owns configuration, the DNS
  resolver, Link registry, topology, status and observation handles, and `CircuitRuntime`.
  `CircuitRuntime` is a facade; it does not merge internal managers, locks, or packet-processing
  paths. `DaemonSupervisor` cancels, joins, and enforces shutdown deadlines for top-level tasks.
  `runtime::TaskGroup` is used only by services with multiple long-lived subtasks; it currently
  manages the FakeIP DNS listener. Services that already use a `JoinSet` are not wrapped again.
  `NetworkResources` tracks the TUN, routes, firewall rules, and NAT resources successfully
  created at startup and rolls them back during shutdown. The application still holds Router,
  FakeIP runtime, and network resources separately after startup, so runtime ownership is not yet
  fully unified.
- `status`, `observability`: Provide bounded PCAP capture, status snapshots, the Unix management
  socket, loopback metrics, and counters. They do not make routing or admission decisions.
- `crates/tinect-fake-tcp`: Implements Fake-TCP packet encapsulation without I/O. It provides a
  minimal TCP state machine and IPv4/IPv6 packet encoding and decoding, but no TCP retransmission,
  congestion control, or flow control. The caller owns raw sockets, TUN, routing, and RST rules.

### Three parallel planes

```text
control plane: QUIC reliable stream
  Hello/HelloAck -> Topology Snapshot/Delta/ACK -> Open/ACK/Reject
  -> Renew/Close/Broken -> FecReport

Physical data plane: per-Link authentication
  FORM_FORWARD | PROBE | PROBE_ACK | KEEPALIVE | FEC_SOURCE | FEC_REPAIR

End-to-end data plane: enabled after the Circuit is established
  TUN IP packet -> route snapshot -> E2E DATA -> Physical envelope -> Link
```

`quic://`/`quic-faketcp://` puts the Physical datagram in the bare underlay;
`quicfull://`/`quicfull-faketcp://` puts the same Physical payload in the QUIC DATAGRAM. The FEC of
each Link works independently, the multi-hop relay re-encodes on the next Link, and the relay never
decrypts the E2E payload. Physical `Forward` only unwraps the hop-by-hop metadata and binds the
opaque E2E frame with AAD; `Probe`/`ProbeAck` detects the bare Physical capacity, `Keepalive` only
proves that the adjacency still has authenticated traffic, and `FEC_SOURCE`/`FEC_REPAIR` only
serves the datagram of this Link recovery.

The data plane incorporates the 128-bit CircuitId, path, and source temporary X25519 public key
composed of a random 64-bit prefix and a monotonic 64-bit counter into the signed OPEN; the source
is derived from the signing public key, and the destination is derived from the end of the path.
OPEN no longer carries TTL, path MTU, or nonce that cannot be safely decremented. The exit installs
the DATA key exported by ECDH and returns ACK after verification on the reliable Open. The source
only sends the QUIC DATAGRAM after receiving the destination ACK, so the loss or disorder of the
DATAGRAM will not cause the session status to be permanently out of sync. There is only one DATAGRAM
receiver per relay inbound Link; it reads the CircuitId from the end-to-end ciphertext frame header
and forwards it unchanged to the authorized next hop according to the `(Inbound Link instance,
CircuitId)` table, or only decrypts when the local final egress is authorized, so different Circuits
do not compete to read the same QUIC receive queue. Relay does not decrypt IP payload. When the
receiver finds an unknown session or relay label, it uses the unified signature `CircuitBroken` for
feedback; the multi-hop relay verifies and re-signs hop by hop, and the source revokes the old lease
based on the first hop Link instance and CircuitId. When feedback is lost, the long lease,
authenticated DATA refresh, periodic Circuit Renew and equal-length local failure grace are layered
to cover the situation. Instantaneous Renew failure will not interrupt the active circuit.

### critical life cycle

1. `Config::load` completes YAML, identity reference, endpoint, ACL, route-set and
   platform-independent verification; `--dry-run` only prints the network plan and does not
   create network resources.
2. `up` creates `Runtime`, loads daemon identity once, starts listener, active connector,
   status/metrics, topology advertisement and circuit reconcile. Link can be used as a path edge
   for automatic path finding only after bidirectional reliable Topology Snapshot/ACK is
   completed; Delta and LSA TTL lease renewals use the control stream.
3. If the configuration requires a local data plane, the application creates TUN, address,
   managed routes, direct/NAT/ firewall and lifecycle hooks, and then publishes the route
   snapshot. Whether TUN is created is determined by the `owns_tun` role; pure relay can close
   TUN, and the relay forward of transit-capable nodes does not go through the second TUN
   DATAGRAM reader.
4. Source Circuit Reconciliation maintains a worker according to destination: parses the first
   ready path and sends the signature OPEN; destination installs the ECDH DATA session and sends
   the signature OpenAck, and the source atomically releases the active lease. Path migration
   retains the drain window of the old lease; link replacement, path proof expiration,
   configuration authorization change, `CircuitBroken` or lease expiry must revoke local sending
   qualifications, and renewal/lease will take care of the situation when feedback is lost.
5. The stopping sequence is to close the registered Link, cancel and wait for the daemon
   top-level task, and then clean up the network resources and status socket according to the
   actual ownership of `NetworkResources`; the remote CLOSE is a best-effort transmission and
   cannot be a precondition for local recycling.

## Safety and Invariants

1. Configure the peer name to only map the Ed25519 public key locally; use the public key or
   NodeId fingerprint on the wire. QUIC Link cannot be established with an unknown public key,
   but the Circuit carried by the known Link can be forwarded as an unknown source/destination
   according to `allow_relay`.
2. The topology advertisement only provides the signed node graph, directional cost and full user
   IP capacity; the reachable prefixes are from local `peers.*.routes`, `direct.routes` and path
   override, and the domain name/CIDR SiteSet is only expanded in the local configuration. The
   topology will not import public network routes for nodes.
3. Each Link's Forward has only one owner; the relay forwards the label as it is according to
   `(Inbound Link instance, CircuitId)`, and the destination is only decrypted when OPEN has been
   authorized and the session exists. Rejection of unknown session or label must be reported back
   via signature `CircuitBroken` and cause the source to eventually revoke the old lease.
4. The new remote egress must call `EgressPolicy::authorize()` and simultaneously cover allow,
   deny, malformed/fragment, and source identity paths; the bypass of native direct is explicit,
   configuration-constrained local semantics and must not be copied into a second set of remote
   ACLs.
5. Configuration, policy, routing, topology, and circuit decisions must not execute host network
   configuration or shell commands; TUN, route, nft/PF, ctnetlink, and fake-TCP raw socket must
   go through `platform`. Ordinary QUIC, DNS, and status sockets belong to their respective
   application boundaries and should not be stuffed into the platform for the sake of
   "unification."
6. Route snapshot, active lease, send budget and Link instance must be submitted according to
   generation/epoch conditions; expired snapshot, late feedback, and old Link events cannot be
   reopened for sending qualifications. All bounded queues and background tasks must have
   explicit cancellation, recycling, and failure counts.

## Simplification and optimization conclusions

The current functional boundaries should remain separate: `carrier`'s
hop-by-hop authentication, `physical`'s hop-by-hop envelope, `circuit`'s relay binding,
`dataplane`'s end-to-end decryption/ACL, and `platform`'s privileged operations respectively bear
different trust responsibilities. Combining them into a "big Router" will reintroduce relay
decryption, resource cleanup and ACL drift risks.

What requires convergence is code ownership and interfaces, not protocol semantics:

- The implicit daemon dependency of `main.rs` has been moved to the explicit `daemon::support`.
  The entry only retains the CLI and startup orchestration to avoid sharing auxiliary logic and
  reversely relying on the entry module.
- `circuit::Router`, relay binding and dataplane relay outgoing path have been changed to use
  minimal `Arc<dyn LinkHandle>`; this trait only exposes instance, peer identity/name, health
  status and control/forward sending. `LinkDirectory` is responsible for searching by peer or
  instance. The specific Link still only appears at the transport/physical life cycle boundary.
- `Runtime::circuits` is the `CircuitRuntime` facade. It only closes the assembly and does not
  merge `SessionManager`, `CircuitOpenManager`, `ReturnFlowTable`, `CircuitDnsClient` or locks
  into a single status machine, so the hot path and test boundaries remain clear.
- `topology` currently contains `Notify`, while `circuit` and `dataplane` still contain some Tokio
  state. You can let the core `TopologyDb`/`CircuitModel` only return state changes and put
  notifications, timers and workers into the runtime; in this way, testing and future offline
  tools no longer depend on Tokio, but the existing event-driven semantics are not changed.
- `carrier/error.rs`, `dataplane/relay.rs`, `runtime/task_group.rs`,
  `runtime/circuit_runtime.rs`, and `daemon/support.rs` have extracted responsibilities with low
  coupling. Carrier handshake, FEC, and PMTU code, along with the Linux/macOS platform code, remain
  grouped around their physical responsibilities. They should not be split into a shared facade
  solely to increase the file count. Further refactoring should follow ownership and testing
  boundaries rather than an arbitrary module hierarchy.
- `DaemonSupervisor` continues to manage top-level tasks; FakeIP's two long-lived DNS listeners
  are unified by lightweight `TaskGroup` to spawn/cancel/join/drain, and cancels and joins the sibling if one listener fails. Services that already have their own JoinSet are not packaged
  repeatedly to avoid introducing excessive abstraction.

## Recommended final plan

Ultimately four logical layers and an explicit privileged adaptation layer remain:

```text
core model
  config / route_sets / identity / crypto / wire / physical / mtu / fec
  policy / routing / topology-db / circuit-model / reconcile

transport
  carrier / underlay / quicp / LinkHandle adapter

dataplane
  packet / immutable route snapshot / secure / direct / FakeIP

runtime
  Runtime / CircuitRuntime / link+topology+circuit workers / TaskGroups / status

platform adapter (can only be called by the adapter of runtime/dataplane/transport)
  TUN / route / nft+ctnetlink / PF / fake-TCP raw socket
```

The dependency rules are: `core` does not depend on `carrier::Link`, `platform`, `tokio::net`;
`transport` does not know TUN, ACL and route selection; `dataplane` only consumes immutable
snapshots and calls explicit platform adapters; `runtime` Responsible for assembly and life cycle;
platform only returns structured resource tokens and does not hold business decisions. FakeIP and
SiteSet, as optional extensions to dataplane/config, no longer introduce hot path branches of
optional fields in the common Circuit path.

This time it is completed in the following order, and the on the wire wire, configuration fields and
routing semantics are not changed throughout the process:

1. `main`/`daemon` uses the explicit `daemon::support` API; separates out independent compilation
   units such as transport error, relay and task group.
2. Introduce `LinkHandle`/`LinkDirectory` in the form of trait-object to decouple the outgoing
   path of Circuit/relay from the specific Link; the physical reception and life cycle continue
   to use the specific Link.
3. Converge the original `Runtime::ControlPlane` to the `Runtime::circuits: CircuitRuntime`
   facade; do not merge internal managers, locks or hot paths.
4. Only include the brother listener of FakeIP into `TaskGroup` to verify cancellation, join,
   timeout recycling and no orphan tasks; do not wrap the existing JoinSet with another layer.

The solution that is not recommended is to rewrite it as a single global actor, stuff all
QUIC/DNS/status into `platform`, or take advantage of structural reconstruction to introduce hot
reloading, protocol compatibility layer, and flow viscosity. These will expand the fault domain, but
cannot improve the current most important safety invariants and convergence boundaries. For detailed
Implemented design records, see
[RFC-0045](specs/RFC-0045-architecture-boundaries-and-simplification.md).
