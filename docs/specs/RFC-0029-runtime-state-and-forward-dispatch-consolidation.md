# RFC-0029: Runtime state and Forward scheduling convergence

- Number: RFC-0029
- Status: Implemented
- Created: 2026-08-10
- Last updated: 2026-08-28

## Background and Problem

The daemon's Circuit lifecycle currently spans multiple independent `Mutex<HashMap<...>>`,
`HashSet`, atomic generation and `Notify`. These containers store desired resolution, OPEN attempt,
active lease, migration, worker ownership and waiters respectively. Each item makes sense
individually, but a logical transformation requires cross-container updates, and missed
notifications are covered by scheduled polling.

The reception of Physical Forward also first enters `broadcast` and then is subscribed by relay or
secure data plane depending on the deployment mode. The only handler of such a packet is indirectly
determined by the worker startup timing and static Boolean switches.

## Goals and Non-goals

Target:

- Convert all variable lifetime state convergence of each destination circuit into a slot; slot
  conversion atomically updates generation and emits events.
- Each Link's Forward can only be received by one data plane consumer; secure receivers are
  classified as relay, exit or drop based on the current authorization/label/session state, and
  pure relay nodes only perform opaque forwarding.
- Routing snapshots only read the metadata of the committed lease; they do not rely on the last
  path cache that is separate from the lease.
- Replace periodic reconciliation polls with explicit state change notifications.

Non-goals:

- Does not modify OPEN/CLOSE/RENEW, Physical, encryption, or Topology's on-the-wire format.
- Without bypassing `EgressPolicy::authorize()`, the relay must still not decrypt the end-to-end
  payload.
- Do not change the bounded data plane queue to an unbounded queue; DATAGRAM can still be
  discarded during congestion, but the reason for discarding must be recorded at the unique owner.

## the term

- **CircuitSlot**: Local source circuit life cycle status keyed by destination, including desired,
  in-flight attempt, active lease, migration and worker claim.
- **Runtime event**: A monotonic version notification issued by the state owner after a change is
  completed; the consumer re-reads a consistent snapshot rather than relying on the integrity of
  the event content.
- **Forward dispatcher**: The only task that calls `Link::recv_physical()` and makes data plane
  decisions for the `Forward` frame.

## design

### Circuit state

`CircuitOpenManager` saves a sync-protected `HashMap<String, CircuitSlot>`. It is the only source of
destination-related state; the process-level random CircuitId prefix and monotonic counter, the
short-lived waiter keyed by `(Link instance, CircuitId)`, and the non-wire lifecycle token bound to
the corresponding Link are retained as global security indexes. Link teardown invalidates the waiter
in registration/resolution by revoking the token, and does not save the collection of all closed
links during the process life cycle. Any slot mutation increments the state version and notifies the
reconciler/route snapshot.

The same destination can have at most one worker claim and one active lease. Commit ACK, revocation,
capacity changes, path switching, and migration are all done through the slot method; the method
does not perform network I/O while holding the lock. Network I/O is always performed after the
action produced by the transformation, returning the result to verify again with the attempt id and
identity.

### Forward scheduling

authentication Link starts a physical dispatcher. It handles the Probe/Keepalive and writes each
`Forward` frame to the bounded single-consumer queue within the Link. After the secure receiver
receives the queue, if `(incoming Link instance, CircuitId)` has a relay label, it will be sent to
the next hop as it is; otherwise, it will only be decrypted and delivered through the egress ACL
when there is a receiver session on the same Link instance and authorization is allowed; other
frames will be discarded after being rejected. Pure relay nodes receive the same queue and only
forward opaque labels. A Link no longer broadcasts Forward frames to multiple data-plane
subscribers.

### Routing and events

The active lease saves its matching configured-path route override upon submission. The routing
snapshot function without state derives results from active lease, Topology, and Link snapshots and
does not maintain a cross-snapshot compensation cache.

Link registry, Topology and circuit slot changes all wake up the controller through the monotonic
event version of the Runtime. The controller reads the snapshot and completes reconciliation; the
preferred path stable period wakes up at its precise deadline, and does not retain polling every
second as a guarantee of correctness.

## Security and Compatibility impact

The wire format, keys, and ACL semantics remain unchanged. The unique dispatcher tightens the data
plane read ownership to prevent the same Forward from being processed by multiple workers. Slot
submission verification continues to bind Link instance, CircuitId, nonce, source key, configuration
generation and path identity; expired asynchronous results must not overwrite newer slots.

This RFC does not require configuration format compatibility; configuration standardization will be
described in subsequent RFCs or in the Implementation Notes of this RFC. When deploying, there is no
need to migrate on the wire nodes because the protocol remains unchanged.

## Testing and Acceptance

- Duplicate receive-id registration cannot overwrite the existing route.
- For interleaved link down, ACK, revocation, capacity change, and retry events for the same
  destination, at most one active lease exists, and old attempts cannot be submitted.
- Relay, exit and non-authorization forward are all tested by the same dispatcher; relay payload
  remains end-to-end opaque, and exit still goes through ACL.
- The controller does not perform periodic reconciliation when there is no state change; every
  State change will wake it up.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test
  --workspace` and related privileged network integration tests passed.

## Open Questions

Whether to change the uncommon carrier mode to a compile-time feature needs to be evaluated
individually based on the actual deployment usage and cannot be implicitly removed in the runtime
convergence reconstruction.

## Implementation Notes

2026-08-10: Merge the desired, attempt, active, migration, worker claim and rebuild state of each
destination with `CircuitSlot`; retain the short-lived OPEN waiter, process-level random CircuitId
prefix and monotonic counter, and bind the global security index of the Link lifecycle token. active
lease also saves the local route override in effect, and the snapshot builder no longer has a
cross-snapshot compensation cache.

2026-08-28: CircuitId is changed to a random 64-bit prefix plus a monotonic 64-bit counter, and the
historical ID HashSet in the process life cycle is removed; the Link lifecycle token continues to be
responsible for closing the waiter failure in race conditions.

Forward is changed to a bounded single-consumer queue in Link. Physical dispatcher is the only owner
of `recv_physical()`; legacy bridge, relay and secure receiver explicitly claim the queue, and
repeated claims are safely rejected. The Circuit controller removes polling every second and only
waits for the state notification of the monotonous active generation or the precise deadline of the
preferred path stability period; the existing state changes of the Link and Topology continue to
request reconciliation. The `CircuitBroken` notification with invalid downstream binding no longer
holds the Link registry lock, and performs bounded retry and timeout for control flow admission
rejection to avoid single control plane congestion and permanently leaving the source active lease
on the old circuit; the final convergence semantics after feedback loss is defined by RFC-0046. The
OPEN/RENEW waiter holds the non-wire lifecycle token corresponding to the Link; when the Link is
closed, dropped or teardowned, the token will be revoked first, then the waiter and authorization
will be cleaned up, and the token will be checked again in the authorization lock to avoid ACK and
Link replacement race conditions, leaving the old authorization, and no longer maintaining the
unbounded revoked-Link set. Full workspace unit test passed with Clippy.

2026-08-13: Further tighten the control plane lock scope. The old Link CLOSE of path migration is
sent after the Link registry snapshot is completed; OPEN path verification releases the paths read
lock before waiting for authorization or the next hop registry; OPEN waiter is released immediately
after checking and removing the callback, and then enters the Link revocation and authorization
submission critical section. The above adjustments do not change the wire, authentication or circuit
State semantics, but only implement the existing constraint that "network I/O and unrelated
asynchronous lock waits do not occur within the state lock". The critical sections of the Link
registry are all short HashMap operations without await, so a synchronous mutex is used instead; its
guard is not `Send`, which allows accidental lock holding across await in the supervised task to
fail at compile time.
