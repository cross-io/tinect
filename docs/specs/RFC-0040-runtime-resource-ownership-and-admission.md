# RFC-0040: Runtime resource ownership and bounded service admission

- Number: RFC-0040
- Status: Implemented
- Created: 2026-08-23
- Last updated: 2026-08-23

## Background and Problem

The daemon startup process also manages configuration snapshots, dynamically assigned TUN names,
routing, firewalls, NAT, and background tasks. Previously, part of the cleanup logic re-deduce
resources based on configuration, and part relies on runtime collections; when startup fails midway,
the actually created resources may be inconsistent with the configuration derivation results.

The FakeIP DNS service also creates separate tasks for each UDP request and TCP connection. Without
a concurrency limit, control plane or DNS traffic bursts may cause the number of tasks and retained
request status to continue to grow.

Path parsing also reads the topology calculation capacity and proof validity period separately,
potentially allowing the same candidate path to use topology views at different points in time.

## Goals and Non-goals

Target:

- Let `Runtime` hold an immutable, verified snapshot of the configuration.
- Let network resources be cleaned only driven by actual installation results, and support unified
  rollback.
- Establish shared bounded task admission and cancellation paths for the FakeIP DNS frontend.
- Calculate path capacity and attestation validity within a topology snapshot and timestamp.
- Convergence the scheduling dependencies of Circuit Reconciliation into context objects to reduce
  the propagation of irrelevant parameters.

Non-goals:

- No changes to the configuration format, control messages, Circuit wire format, or encryption
  semantics.
- Does not change route candidate priority, circuit lease status, or topology advertising
  protocols.
- Do not move platform I/O into domain modules.
- The authentication, forwarding, idempotent, and convergence semantics of control messages are
  not changed.

## Terminology and models

- `Runtime config`: `Arc<Config>` held by `Runtime` after configuration loading and verification
  are completed.
- `Effective platform state`: TUN name assigned by the platform and actual installed host network
  resources.
- `NetworkResources`: Ownership ledger and rollback entry of effective platform state.
- `PathEvidence`: Capacity vector and proof deadline obtained by reading snapshots and timestamps
  of the same topology.

## design

### Separation of configuration and resources

`Runtime::new` wraps the configuration as `Arc<Config>`, and the long-term circuit worker reads the
configuration from this snapshot. The platform-assigned TUN name is not written back to the
snapshot, but is saved by `NetworkResources::tun_name`; the startup process continues to perform
platform operations using the effective configuration with the actual TUN name.

`NetworkResources` record:

- Actual state of exit network, TUN input firewall, direct firewall and direct NAT;
- The actual installed managed overlay route prefix;
- The effective TUN name and whether the lifecycle hook has entered the cleanable stage.

The rollback sequence is to first cancel and wait for the daemon task, and then clean up the
registered resources. Unregistered resources will not be deleted because corresponding entries exist
in the configuration. After cleaning, the ownership ledger is cleared and it is safe to call again.

### Circuit reconciliation context

`CircuitReconcileContext` holds configuration, Link registry, topology, state, Circuit open
manager, session, Circuit DNS, supervisor and source identity. The reconciler worker only receives
the context and monitors Link, topology and open generation changes; the OPEN worker is derived from
the same context to avoid reassembling state handles with different calling paths.

### FakeIP DNS admission

The UDP query task and the TCP connection task share a semaphore with a fixed capacity of 256. New
requests/connections that cannot obtain a permit immediately are discarded and debug logged without
waiting for the unbounded queue. When the listener receives the cancellation signal, it terminates
and joins the current subtask; a single task also listens for the cancellation signal and releases
its permit and socket resources.

This cap is an in-process resource protection and does not change DNS wire format, cache semantics,
or upstream selection. The observable consequences of overload are partial query timeouts or
retries, rather than an infinite backlog.

### path evidence

`PathEvidence` calculates downstream capacity, capacity generation and proof expiry under one
topology read lock and one `unix_now()`. Candidate parsing directly uses this evidence; route
snapshot caches the evidence by `(ordered path, Link instance)` in a single build, and multiple
prefixes share the calculation results.

## Security and Compatibility impact

- Does not modify on-the-wire control messages, signatures, authorization, or end-to-end payloads.
- Resource cleanup only deletes resources registered by the current daemon, reducing the risk of
  accidentally deleting the host network status based on old configurations.
- DNS concurrency caps reduce the risk of resource exhaustion, but may drop queries when
  overloaded; clients should rely on DNS retries.
- The life cycle of Link, Circuit and relay label maintains the original state machine; context
  extraction does not change the admission judgment.
- The control stream worker has been migrated to `daemon::control_handler`, only changing the
  source code dependency direction, not changing the on the wire semantics of RFC-0016, RFC-0022
  and RFC-0046.

## Migration and deployment

This is an in-process structural adjustment and does not require configuration migration or
simultaneous upgrades on both sides of the communication. During binary upgrade, the old process
still runs according to the life cycle of the old version; the new process only cleans up its own
registered resources.

## Testing and Acceptance Criteria

- `NetworkResources` Duplicate cleanup/rollback of empty resources is safe. The actual registered
  resources are cleaned using effective TUN names.
- The FakeIP DNS semaphore rejects new tasks when capacity is exhausted and releases task
  resources when canceled.
- Circuit reconciliation empty configuration, link replacement and topology generation changes
  maintain the original worker wake-up semantics.
- Candidate resolution and route snapshot tests cover capacity/proof shared snapshots and
  multi-prefix caching.
- Privileged network path testing continues with `cargo fmt --check`, `cargo clippy --all-targets
  --all-features -- -D warnings `, and ` cargo test`; Linux CI.

## open issues

- DNS overload indicators currently only retain debug logs. Whether to add stable metrics fields
  needs to be evaluated separately.

## Implementation Notes

- `src/runtime.rs`: Configuration snapshot.
- `src/daemon/network_lifecycle.rs`: Network resource ownership and rollback.
- `src/daemon/circuit_reconciler.rs`: Circuit context and scheduling boundaries.
- `src/daemon/control_handler.rs`: Link controls stream and topology/Circuit message processing.
- `src/fake_ip.rs`, `src/fake_ip/packet.rs`: bounded DNS tasks and pure packet helper.
- `src/daemon/path_resolution.rs`,`src/daemon/route_snapshot.rs`:PathEvidence.
