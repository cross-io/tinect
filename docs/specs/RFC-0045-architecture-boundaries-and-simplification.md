# RFC-0045: Architectural Boundaries and Structural Convergence

- Number: RFC-0045
- Title: Architectural Boundaries and Structural Convergence
- Status: Implemented
- Created: 2026-08-26
- Last updated: 2026-09-01

> RFC-0046 subsequently updated the Circuit control plane wire; this RFC still only describes the
  architecture boundary. The Circuit control message, failure feedback and OPEN field in this
  article are subject to RFC-0046 and the current `docs/protocol.md`.

## Background and Problem

Tinect currently separates QUIC/bare Physical bearer, hop-by-hop Physical encryption, end-to-end
Circuit, TUN data plane and host network configuration, but these boundaries are not completely
consistent in Rust modules: the daemon submodule of `main.rs` imports shared startup auxiliary
functions through wildcards, `circuit::Router` directly holds the specific `carrier::Link`, source
Circuit, relay binding, receiving session and return flow are composed of multiple Objects are
passed separately, and the child tasks of some services are not within the same supervision
boundary. This increases maintenance costs and can easily lead to "hostless I/O decisions" being
misinterpreted as "purely synchronous domain modules".

This RFC only deals with code structure and ownership and does not redesign on-the-wire protocols,
configuration fields, routing, ACLs, encryption boundaries, or packet semantics.

## Goals and Non-goals

Target:

1. Clarify the responsibilities of core, transport, dataplane, runtime and platform;
2. Let the Circuit model not depend on the specific carrier implementation;
3. Let the shared Circuit state be uniformly assembled by a runtime facade instead of continuing
   to diffuse parameters;
4. Let long-term tasks have clear owner, cancellation and join boundaries;
5. Improve testability and room for subsequent optimization without changing wire/config.

Non-goals:

- Does not introduce hot reloading, protocol compatibility layers, flow stickiness, multipath or
  new carriers;
- Do not force ordinary QUIC, FakeIP DNS or status sockets into `platform`;
- Do not rewrite all state into a single global actor;
- Do not use structural splitting as a reason to change existing security deny, circuit
  revocation, or network resource cleanup semantics.

## the term

- **core**: Does not implement host network I/O configuration, protocol, policy, and state model.
- **LinkHandle**: The minimum link capability required by Circuit, including stable Link
  instance/identity, peer name, health status, and control/forward transmission; does not expose
  Quinn, raw socket, FEC or PMTU. Capacity and admission are still calculated by the transport
  before routing.
- **CircuitRuntime**: The Circuit facade of the runtime layer uniformly holds the assembly handles
  of source reconcile, relay router, session, return flow and Circuit DNS; the internal
  implementation can still be split.
- **TaskGroup**: Cancel/join owner of a service and its child tasks; the top-level supervisor only
  registers waitable service futures.

## design

### 1. Goal stratification

```text
core
  config / route_sets / identity / crypto / wire / physical / mtu / fec
  policy / routing / topology-db / circuit-model / reconcile

transport
  carrier / underlay / quicp / LinkHandle adapter

dataplane
  packet / route snapshot / secure / direct / FakeIP

runtime
  Runtime / CircuitRuntime / daemon workers / status / TaskGroups

platform adapter
  TUN / route / nft+ctnetlink / PF / fake-TCP raw socket
```

Dependency rules: core does not depend on `carrier::Link`, platform or `tokio::net`; transport does
not know TUN, ACL and route selection; dataplane only consumes immutable route/lease snapshots and
accesses the platform through explicit adapters; runtime is responsible for assembly and life cycle;
platform only returns structured resource tokens and does not participate in business decisions.

### 2. Decoupling of Circuit and Link

Split the current outgoing capability of `circuit::Router` into two layers:

- `circuit` maintains domain rules for NodeId, OPEN field, path/transit verification, binding key,
  lease state and signature feedback;
- `runtime::CircuitRuntime` is responsible for facade assembly. The binding/label table and each
  manager still maintain independent life cycles; Router/relay completes next hop sending and
  health query through `LinkHandle`.

The implementation uses trait-object: `src/link.rs` defines `LinkHandle`, `LinkRef` and
`LinkDirectory`, and `carrier::Link` implements the adapter at the carrier boundary.
`circuit::Router`, relay binding and dataplane relay outgoing path use `Arc<dyn LinkHandle>`;
physical reception, life cycle management and platform capabilities of Link registry still use
specific `carrier::Link`. The trait only provides the actually needed instance, peer identity/name,
health, forward sending and control sending, and the carrier-specific MTU details remain in the
transport.

### 3. Unified CircuitRuntime assembly

`Runtime::ControlPlane` has convergence with the `Runtime::circuits: CircuitRuntime` facade,
equipped with at least:

- `CircuitOpenManager`(source desired/attempt/active lease);
- relay `Router`/label registry;
- `SessionManager`, `ReturnFlowTable` and `CircuitDnsClient`;
- Event notifications aligned with topology/link generation.

The facade only unifies ownership and dependency injection, and does not require merging internal
maps into a lock, nor does it require changing the dataplane hot path to message passing.
`RouteSnapshot` is still an immutable release object, and the old lease's send gate and
`lease_epoch` are still final eligibility checks before sending.

### 4. Topology and task ownership

This time `TopologyDb`/`CircuitModel` will not be rewritten into a new global state machine;
existing notifications, timers, backoffs and worker ownership remain in their respective runtime
services. The newly added `runtime::TaskGroup` is a lightweight `JoinSet` + `CancellationToken`
owner, which is only used for FakeIP's UDP/TCP DNS listener and provides spawn, cancel, join/drain
and timeout recycling. Services that already have JoinSet are not packetd repeatedly, and the
top-level `DaemonSupervisor` continues to be responsible for the service entrance. Long-term bare
`tokio::spawn` that cannot be canceled or joined by owner must not be added.

### 5. File organization

Actually taking an internal split that doesn't change the behavior:

```text
src/link.rs # LinkHandle / LinkDirectory trait-object boundary
src/daemon/support.rs # daemon shared auxiliary logic
src/carrier/error.rs # transport error and LinkHandle error adaptation
src/dataplane/relay.rs # Transparent relay outgoing path
src/runtime/circuit_runtime.rs # CircuitRuntime facade and LinkDirectory adapter
src/runtime/task_group.rs       # FakeIP child task owner
src/main.rs # CLI and startup orchestration
```

The existing public module paths of `carrier`, `circuit`, `platform` and `runtime` are retained; no
`core`, `transport` or global facade is introduced for the number of directories. The purely
mechanical code reuses the original coverage, and the newly added traits, TaskGroup and auxiliary
logic have independent single tests.

## Security and Compatibility impact

This RFC itself does not change on the wire byte format, authentication, E2E/Physical encryption,
relay transparency, EgressPolicy admission, Circuit failure feedback, or platform resource
ownership; subsequent changes to the control plane wire are documented by RFC-0046. Any
implementation MUST preserve:

- relay does not decrypt E2E payload;
- CircuitBroken/old Link/lease expiry final revocation source send eligibility;
- Conditional submission of route snapshot and lease epoch;
- Startup failure rollback, SIGTERM cleanup and precise deletion of platform resource tokens;
- Boundaries between normal QUIC, FakeIP DNS, status socket and platform host configuration.

## Protocol and data format impact

This RFC does not introduce additional changes; the current format of `ControlMessage` is subject to
RFC-0046, and the physical form, E2E DATA, topology LSA, management socket and configuration fields
are still directly carried by the architecture described in this RFC. `LinkHandle` only encapsulates
the in-process Link capability and does not add an adapter identifier or a new handshake phase to
the wire layer. If subsequent structural splitting requires changing the on-the-wire format, another
RFC must be created and this RFC must not be used for direct modification.

## Testing and Acceptance Criteria

1. `cargo fmt --check`, strict clippy, `cargo test` all passed;
2. The unit test covers LinkHandle adapter's sending success/failure, health status, old Link,
   Link replacement, lease epoch, late ACK/Reject/CircuitBroken, unknown session and relay
   binding's admission/revocation/expiration/duplication/out-of-order feedback;
3. Privileged integration testing covers direct path, multi-hop relay, downstream restart/Link
   replacement, control plane congestion/loss, duplication and late feedback, confirming that the
   source is eventually withdrawn or rebuilt rather than silently losing packets after a limited
   retry;
4. Startup rollback, TaskGroup subtask failure propagation, cancellation, join, timeout abort,
   FakeIP DNS subtask recycling, TUN/route/nft/PF/ctnetlink cleanup all have assertions;
5. The report generated by `cargo llvm-cov --workspace --all-features --lcov` is uploaded to
   Codecov, and the project and patch coverage status are managed uniformly by `codecov.yml` in
   the repository root directory;
6. Compare the existing remote scripts and indicator/state output before and after the
   structural reconstruction, and no new wire/config differences should appear.

## Migration order

1. The implicit import of `main`/`daemon` has been changed to the explicit `daemon::support` API;
2. Transport error, relay and task owner have been removed, and `LinkHandle` has been introduced,
   without changing the calling sequence;
3. `Runtime::ControlPlane` has converged to `CircuitRuntime` facade, and the internal
   manager/lock remains independent;
4. The brother listener of FakeIP has been included in `TaskGroup`, and the services of the
   existing JoinSet have not been packetd repeatedly;
5. `TopologyDb`/`CircuitModel` will continue to retain the existing notification dependency, and
   will only be re-evaluated later when the independent benefits are clear.

## Implementation Notes and Open Questions

- `LinkHandle` in the form of trait-object has been selected: it provides a minimum stable
  boundary between Router, relay and test fake to avoid spreading carrier details to Circuit;
  there are no new protocol fields or state machines in the current hot path.
- The lightweight `TaskGroup` has been selected, covering only FakeIP's two long-lived listeners;
  it does not replace the top-level `DaemonSupervisor`, nor does it wrap an existing JoinSet.
- Do not merge `TopologyDb` and `RouteSnapshot` into a unified immutable snapshot; do not adjust
  FEC, PMTU, priority admission, or per-packet route lookup algorithms. If you want to change
  these decisions later, submit a separate RFC.

## Compatibility conclusion

LinkHandle is an in-process trait-object only; it does not generate wire identifiers, change
authentication or forwarding order. RFC-0046 is responsible for compatibility conclusions for the
current Circuit control plane wire; existing direct path, multi-hop relay, link replacement,
downstream restart, control plane congestion/loss, and duplicate/late feedback tests continue to
serve as acceptance boundaries.
