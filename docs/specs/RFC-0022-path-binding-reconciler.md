# RFC-0022: Declarative Circuit Reconcile and Dynamic Send Budgets

- Number: RFC-0022
- Status: Implemented
- Created: 2026-08-03
- Last updated: 2026-08-27
- Change record: 2026-08-03 Completed resolver identity/capacity separation, lease condition
  submission, dynamic sending budget, relay carrier wire pre-check and cancellable PMTU state
  machine implementation; unified destination resolver, migration identity and event
  deduplication. 2026-08-10 Convert the local PMTU over-limit convergence to a single attempt, and
  use 60 seconds to recover and re-explore the known upper bound to avoid repeated construction of
  detection packets that determine the over-limit on the stable path, while maintaining the
  dynamic budget time limit for failure recovery. 2026-08-15 According to RFC-0037, dynamic
  budget, capacity events and historical descriptions are unified into user IP bytes, and the
  path-payload and application DATAGRAM capacities of full QUIC are clarified; 2026-08-27
  According to RFC-0046, the current wire and full upgrade boundaries are updated.

> RFC-0046 updates the Circuit token involved in this article: OPEN's source/destination, TTL, and
  path MTU are no longer wire fields, and relay binding is only associated by `(Link instance,
  CircuitId)`; the dynamic capacity, path identity, and lease condition submissions of this RFC
  are still applicable. The descriptions of `path_inner_mtu`'s position in the on the wire OPEN,
  legacy node compatibility, and `OpenFingerprint` capacity fields in the earlier chapters of this
  article are historical background, and the current protocol is subject to RFC-0046.

## summary

RFC-0021 solves the problem of Circuit migration after the preferred path is restored, but puts the
path, Link instance, topology proof and MTU change in the same local judgment, causing the
path capacity refresh to potentially trigger unnecessary Circuit reconstruction, and also makes the
asynchronous OPEN result easy to compete with newer topology or configuration status.

This RFC splits the Circuit lifecycle into three independent concepts:

> Capacity Unit Description (2026-08-15): The dynamic budget and carrier-local wire checking
  framework of this RFC still apply, but the capacity units of LSA, `LinkCapacityChanged`, and
  OPEN ceiling have been unified by RFC-0037 to full user IP packet bytes. The `datagram_mtu`,
  `path_datagram_mtu` and Physical unit descriptions earlier in this article are historical names;
  the current code and protocol documents only use `inner_mtu` in LSA and local active budget, and
  the carrier-local PMTU unit does not leak to the upper layer.

1. **Circuit identity**: Determines whether the current Circuit is still applicable;
2. **Sending Budget**: Determines the maximum size of user IP packets currently allowed to be
   sent;
3. **Active lease**: Owns Circuit keys, Link instances, route references, and cleanup
   responsibilities.

Changes in the path or first-hop Link instance require migrating the Circuit; changes in
authorization semantics or HardRevoked require the lease to be revoked and re-established. When the
MTU increases, the circuit is not rebuilt, but the source node gradually increases the sending
budget based on the current active path capacity; when the MTU decreases, the sending budget of the
active lease is only reduced, and the existing circuit is not revoked. The relay does not save the
end-to-end MTU forwarding ceiling, but only passes the received frame to the next hop carrier. The
current carrier-local Physical frame/application DATAGRAM upper limit of the carrier determines
whether it can be sent.

Each destination is serially processed by a single supervisor/actor to handle reconcile events. OPEN
can be executed asynchronously outside the actor, but the result must be submitted through a
condition with attempt identity to prevent the outdated Circuit from becoming active. The data plane
uses immutable snapshots to atomically publish routes, leases, and sending budgets; kernel routing
and TUN MTU are asynchronous platform projections of the snapshot, not state sources.

This RFC does not add a new wire frame, does not introduce SessionAck, and does not change keys,
ACLs, dynamic capacities, and relay opaque semantics; the current wire definitions of OPEN and
Circuit control messages are uniformly specified by subsequent RFC-0046. The source node's active
send budget is still calculated by a combination of local configuration, path capacity, and circuit
ceiling, but the path MTU hint is no longer passed through OPEN.

## Background and Problem

In the early days of In Progress, when the circuit was established, the source node calculated
`path_inner_mtu` based on the preferred path and the known topology capacity. The relay then
minimized this value and its own next hop capacity and saved it in the relay binding. There are two
long-term problems with this model:

- The PMTU detection of physical links is dynamic, and an increase in MTU will be mistaken for a
  change in circuit identity;
- The refresh, expiration and re-propagation of topology LSA may cause frequent reconciliation,
  and even cause the old OPEN results to be incorrectly submitted under the new path state.

More importantly, the real hard boundary of relay forwarding is the current sending capability of
its next-hop carrier, rather than the entire path capacity estimated by the source node at a certain
OPEN. If the relay only calls the unified `send_physical()` during forwarding, it does not need to
know whether the end-to-end path MTU has become larger, nor does it need to rebuild the Circuit to
use the new capacity.

Therefore, long-term design should:

- Let Circuit identity only represent changes that must be re-keyed and hop-by-hop published;
- Send capacity changes as data plane budget changes;
- Separate the relay's local carrier constraints from the source node's path capacity estimates;
- Eliminate asynchronous lifecycle races with a single destination actor and conditional commits.

## Goals and Non-goals

### Target

- Drive the Circuit lifecycle with the path and first-hop Link instance instead of all topology
  fields;
- Each destination is guaranteed to have only one reconcile supervisor and one active OPEN
  attempt;
- Allow MTU to rise without rebuilding the circuit, avoiding control plane churn and short-term
  interruption;
- When the MTU drops, immediately reduce the source node’s sending budget and reduce the number of
  frames that will be discarded by the relay;
- The relay only relies on the real-time capacity of the next-hop carrier and does not save the
  end-to-end MTU forwarding ceiling;
- Maintain cancelable, dynamic PMTU state machine with historical boundaries and rapid decline
  for each physical link;
- Only the confirmed capacity is propagated to avoid PMTU detection attempt values   or ordinary
  LSA refresh triggering path reconciliation;
- Atomicly publish active leases, route references, and send budgets as immutable data plane
  snapshots;
- Stale OPEN results must not be submitted as active, nor must they leak waiters, authorizations,
  or remote leases;
- Preserve the preferred path priority, stability window, deadline, drain and bounded retry
  semantics of RFC-0021; the data plane does not retain the flow affinity of the quintuple to the
  old egress, and each TUN packet is reselected according to the current healthy candidate;
- Maintain RFC-0046 current wire, key, OpenAck/OpenReject, Renew, Close, CircuitBroken, ACL and
  relay opaque boundaries;
- The outbound and return journeys are managed by their respective source node Circuit
  supervisors, and the two directions are not assumed to be symmetrical in a lease.

### Non-goals

- There is no guarantee that there will be no excessive MTU packet loss during the topology
  information propagation delay; relay can only reject over-limit frames based on its local
  carrier capabilities;
- End-to-end fragmentation, reassembly or reliable retransmission is achieved without adding new
  wire messages;
- All paths are not required to use the same MTU, latency, Link instance or topology proof;
- Do not use TUN's global MTU as an accurate capacity model between different destinations;
- Do not bind traffic counters to short-life circuit leases;
- Do not use topology refresh, LSA sequence or `expires_at` directly as Circuit identity.

## the term

- **ResolvedPath**: The ordered path parsed by the resolver based on the current configuration,
  Link and topology snapshots, and also includes the first hop Link instance, candidate priority,
  current capacity and proof validity period.
- **CircuitIdentity**: A stable value that determines whether an existing Circuit can still be
  reused: `(destination, ordered_path, first_hop_link_instance)`.
- **OpenFingerprint**: An immutable fingerprint composed of all non-signed fields of the current
  OPEN; relay uses it to do the same OPEN idempotent and rebind verification, but the end-to-end
  capacity state must not be used as a permanent limit for Forward.
- **RelayForwardBinding**: The hop-by-hop forwarding reference used by relay data plane only
  includes incoming Link instance, CircuitId, authorization, outgoing carrier, lease and label; it
  does not include end-to-end capacity ceiling.
- **Send Budget**: The maximum user IP packet that the current source node allows to be handed
  over to the encrypted send queue, which is determined by the configuration upper limit, the
  current path capacity and the Circuit upper limit; Tinect encapsulation is only processed in the
  carrier-local wire check.
- **Circuit ceiling**: When establishing a circuit, the upper limit of user IP capacity used by
  the source node for the circuit. This is the sending upper limit of the source node, not the
  permanent forwarding upper limit of relay binding.
- **Confirmed capacity**: `UserIpCapacity` that has been successfully verified a specified number
  of times, is allowed to be released externally, and is used to send budgets; the Physical frame
  or QUIC application DATAGRAM target inside the detector is not an external capacity.
- **PMTU state**: Each physical link, independently maintained confirmed capacity in each
  direction, search boundaries, current probe, number of consecutive successes/failures, and
  latest confirmation time.
- **ActiveLease**: Owns a handle to an active Circuit and its local resource references.
- **Attempt identity**: eligibility to commit an OPEN result, composed of the destination, attempt ID, and target
  CircuitIdentity, `config_generation` and first-hop Link instance.
- **Config generation**: A local configuration generation that is only incremented when path
  constraints, target public keys, ACLs, egress policies, or other Circuit authorization semantics
  will be changed; display names, indicator settings, and fields that do not affect the sending
  security boundary are not incremented.
- **Proof stale**: The old path proof that is still valid has not yet been refreshed; this is not
  a topology revocation, and the sending budget cannot be increased, but the current confirmed
  conservative budget can continue to be used.
- **Hard revoke**: Events such as Link instance shutdown, active path edges being explicitly
  removed or proven to have actually expired, authorization configuration changes, etc., that make
  the existing lease no longer eligible to continue sending.
- **Degraded**: The target path is being migrated, the sending budget is tightened, or the
  migration exceeds the deadline, but the active lease still has the status of valid path
  proof validity and sending qualifications; the data lease plane must not be retained as Degraded
  after Hard revoke.
- **Lease epoch**: The local send generation number that is incremented each time an active lease
  is released; used by the data queue and send gate to reject old leases that have been revoked or
  have exceeded the drain deadline.
- **Capacity generation**: A monotonic version of each Link, direction, and path capacity
  snapshot; only used to reject out-of-order capacity updates and does not belong to
  CircuitIdentity.

## Protocols and data formats

RFC-0046 has unified the wire frame and signature input of the current OPEN and Circuit control
messages: OPEN only contains CircuitId, temporary public key, source public key, ordered path and
signature, source/destination is derived from the authentication field; CircuitId, path, public key
and temporary public key constitute the relay's immutable OPEN fingerprint. This article only
stipulates resolver, active lease, dynamic capacity and conditional commit. It no longer puts
path MTU or other local budget fields into OPEN, nor does it use them as relay forward ceiling.

Physical Forward's final send check is always calculated in carrier-local units: full QUIC uses
Quinn's application DATAGRAM payload limit as Physical frame capacity, bare UDP/fake-TCP
distinguishes `target_len` and `physical_frame_len` as per RFC-0014, and only handles the additional
receive ID/encapsulation header at the carrier layer. Link released `UserIpCapacity` only after
this. The relay's RelayForwardBinding does not cache the end-to-end capacity; the outgoing carrier
recalculates the current wire limit before each transmission.

## design

### 1. Resolver output and identity boundaries

The resolver receives a read-only snapshot of Link and Topology and returns:

```text
ResolvedPath {
    destination
    ordered_path
    first_hop_link_instance
    candidate_rank
    verified_user_ip_capacity
    capacity_vector
    proof_valid_until
}
```

resolver returns the current target state separately:

```text
DesiredResolution {
    generation
    config_generation
    path: Option<ResolvedPath>
    availability:
        Ready
      | ProofStale { valid_until }
      | TemporarilyUnavailable { reason, retry_at }
      | HardRevoked { generation, reason }
    resolved_at
}
```

`path == None` is a clear state, indicating that there is currently no ready candidate that meets
the conditions, rather than an empty path that can be used for OPEN. The resolver must return the
first ready candidate according to the candidate priority; the candidate must satisfy the first hop
Link authenticated, topology synchronization is completed, and all required path edges have current
valid path proofs. `HardRevoked` is an edge event with `generation`, rather than a stable state
that can be consumed repeatedly by the same resolver generation indefinitely; if there are still no
candidates after processing, the resolver should return `TemporarilyUnavailable` with
reason/retry_at.

Circuit identity is defined as:

```text
CircuitIdentity {
    destination
    ordered_path
    first_hop_link_instance
}
```

The following fields MUST NOT individually cause the Circuit identity to change:

- LSA sequence;
- Refresh of LSA expires_at or proof_valid_until;
- Topology generation independent of the selected path;
- Increase or decrease in current path capacity;
- Configuration changes that only change the display name.

If the candidate ordering, configuration path, or actual capacity of the path edge changes, the
resolver can generate a new `DesiredResolution` generation; the actor must still compare the
specific `CircuitIdentity` and `config_generation` to avoid canceling semantically equivalent OPENs
just because the event arrives. `availability` must distinguish between proving that it has not been
refreshed, that there is no ready candidate, and that it has been hard revoked. `path == None`
cannot be used to hide the life cycle semantics. `ProofStale` can carry the current active path for
restricted forwarding, but cannot be used as a ready candidate for a new OPEN.

### 2. ActiveLease and sending budget

```text
ActiveLease {
    circuit_id
    identity: CircuitIdentity
    link_instance
    data_key
    circuit_ceiling
    route_handle
    config_generation
    lease_epoch
    send_gate
}
```

Traffic counters do not belong to ActiveLease. They are accumulated by destination or stable logical
egress, Circuit migrations must not zero out or recreate dynamic metric labels.

The current sending budget is calculated according to the following rules:

```text
safe_user_ip_budget = min(
    configured_tun_mtu,
    active_verified_user_ip_capacity,
    active_lease.circuit_ceiling,
)
```

The above budget is already the complete user IP packet bytes, and is no longer repeated by
reconcile or data plane minus the 41-byte DATA frame and 25-byte Physical Forward overhead; these
overheads are only used for the final wire check of the carrier-local.

The above formula only applies to active leases that have been issued. Calculated separately when
preparing OPEN:

```text
opening_circuit_ceiling = min(
    configured_tun_mtu,
    desired_verified_user_ip_capacity,
)
```

During `Preparing`, the capacity of the desired path must not directly change the budget of the
active snapshot; the active lease continues to use `active_verified_user_ip_capacity` until the new
lease passes the condition submission. The active and desired capacities must each carry their
`capacity_vector`, which records the `capacity_generation` of each directed edge, to avoid
low-capacity candidates in migrations from erroneously tightening the old path, or high-capacity
events from the old path erroneously amplifying the new candidate's OPEN ceiling.

When there is no active lease, the sending budget can only be used to select and establish new
circuits, and plaintext data cannot be queued to non-existing circuits.

When the old path proof has not been refreshed but has not yet expired, the source node must use
the last confirmed conservative security budget and cannot increase the budget to the configuration
upper limit; such `ProofStale` events do not cancel the semantically equivalent OPEN. When the proof
is actually expired, the path edge is explicitly removed, the first-hop Link instance is closed, or
the security semantics of the authorization configuration change, `HardRevoked` must be generated:
the active lease and route are immediately removed from the dataplane snapshot, its send gate is
closed, the local authorization is revoked, and the actor enters `NoActive` to reselect the route.
Signature Close is only a best-effort notification; failure to send must not block local recycling,
and the remote end relies on Link teardown or lease expiry for final recycling. This is consistent
with RFC-0008's constraints on immediate local revocation of topology revocation, configuration
revocation, and link shutdown.

### 3. MTU change semantics

#### 3.1 MTU rise

An increase in MTU does not trigger Circuit reconstruction, nor does it require the relay to update
Circuit binding. The source node can increase `safe_user_ip_budget` after the topology capacity is
updated, but it must not exceed the `circuit_ceiling` of the active lease.

If the current Circuit ceiling is less than the new path capacity, the source node continues to use
the old ceiling; this will not cause errors or additional packet loss, but it will temporarily be
unable to utilize the new capacity. Implementations MAY log the "Capacity Upgradeable" status behind
the scenes, but this RFC does not require circuit rebuilding for throughput gains.

#### 3.2 MTU drop

The MTU decrease only decreases by `safe_user_ip_budget`, and does not close the active lease, does
not send CLOSE, and does not start a new OPEN. The budget reduction must take effect before
subsequent data enters the send queue.

The sending worker must again verify that the frame does not exceed the current budget before
finally calling the carrier, and verify that the queue entry's `lease_epoch` is still the epoch in
the active snapshot. Frames that have entered the old budget queue but have not yet been sent must
be revalidated; they are discarded and counted when the budget exceeds the limit, the epoch does not
match, or the send gate is closed. The "queue" here includes the application layer encrypted send
queue; only datagrams that have been delivered to the carrier can be drained naturally according to
the drain rule. You cannot rely solely on TUN MTU or route refresh to guarantee this invariant.

#### 3.3 Relay forwarding

The relay shall not use the source node's locally calculated end-to-end MTU as a permanent
forwarding ceiling. After relay receives the legal opaque forward:

1. Look up the forwarding binding by `(incoming Link instance, CircuitId)`;
2. Directly call the next hop `send_physical(Forward(frame))`;
3. Accept or reject transmission based on the current Physical frame/application DATAGRAM upper
   limit of the next-hop carrier;
4. `DatagramTooLarge` only causes the frame to be discarded and counted, and does not close
   irrelevant Links or Circuits.

The carrier must perform a local cap check on the actual wire length for QUIC DATAGRAM, bare UDP,
and fake-TCP. The relay must still verify Circuit labels, Link instances, leases, and ACLs; this RFC
only removes the end-to-end MTU's permanent constraints on the relay forwarding binding.

The relay MUST retain an OpenFingerprint (or equivalent irreversible digest) for use in RFC-0008's
OPEN idempotent and rebind comparisons, but the fingerprint MUST NOT be read by the
RelayForwardBinding's data plane send path as the capacity ceiling.

The relay's pre-forwarding check must use the exact wire length of the current carrier, not the OPEN
field or the capacity in the old binding. The checking sequence must be: verify label/Link
instance/lease/ACL, calculate the wire limit of the current carrier, perform `DatagramTooLarge`
pre-check without side effects, and then perform priority admission, physical AEAD seal and physical
serial number allocation. Known precheck failures must not consume physical serial numbers, send
quotas, or close Link/Circuit. The limit of full QUIC is the Quinn application DATAGRAM payload,
which is the upper limit of the Physical frame that the carrier can carry; bare UDP/fake-TCP must be
additionally included in the carrier's own receiving identifier and encapsulation header. All
counters must differentiate between wire overruns, queue backpressure, and protocol errors.

Capacity changes are allowed between the pre-check and the actual carrier dispatch; the final
carrier check remains authoritative. If this race condition results in `DatagramTooLarge`, it only
discards the current frame, counts and continues to serve other frames. It must not be treated as a
Link failure or CircuitBroken. This race condition may have assigned a physical sequence number;
holes in the sequence number are allowed, and the sequence number must not be reused or the
PhysicalSession rolled back to make up for the hole. Implementations can use carrier send locks to
reduce race conditions, but cannot assume that the dynamic PMTU remains constant during a send call.

RFC-0046 deletes the `path_datagram_mtu`/`path_inner_mtu` field in OPEN; the source node's Circuit
ceiling and sending budget continue to be maintained by the local active lease and current capacity
State, and each relay only uses the real-time limit of the outgoing carrier.

#### 3.4 Dynamic Physical Link PMTU Detection

PMTU detection belongs to the physical Link life cycle and does not belong to the Circuit life
cycle. Each direction of each link independently maintains a PMTU state:

```text
PmtuState {
    confirmed_capacity
    lower_bound
    upper_bound
    probe_in_flight
    consecutive_successes
    consecutive_failures
    last_confirmed_at
}
```

In addition to the Probe `target_len` being sent, the bare carrier's `confirmed_capacity`,
`lower_bound`, and `upper_bound` use Physical `physical_frame_len` units; the acknowledgment value
for full QUIC comes from the Quinn application DATAGRAM capacity.
`LinkCapacityChanged.user_ip_capacity` and LSA `inner_mtu` always use `UserIpCapacity`, the receive
ID for bare UDP is only calculated once additionally in the carrier wire check.

The detection rules are as follows:

1. The initial confirmed capacity uses the conservative safety value of the carrier;
2. Upward probing starts from the latest confirmed capacity and history `lower_bound`, without
   resetting to 1200 each round;
3. New confirmed capacity is submitted only after the rising detection success reaches the
   implementation-defined number of consecutive successes;
4. If the detection fails, it will first fall back to the nearest confirmed capacity; if the
   confirmed capacity also fails, it will quickly fall back to the nearest known success boundary
   or conservative safety value;
5. Use a longer cooling time and hysteresis for rising, and use a shorter confirmation window for
   falling to avoid frequent expansion and contraction caused by capacity jitter; the local
   `EMSGSIZE` is the deterministic result of the current socket path, and the same candidate must
   not be sent three times. After this bug tightens `upper_bound`, a successful current capacity
   check must not immediately reopen the same upper bound; the upward search is only restarted
   after the 60 second recovery period has expired;
6. At most one probe in flight is allowed in the same direction, and the probe must have a
   deadline, attempt id, and cancellation path; late ACK must not update a new probe;
7. When the Link is closed, the Link instance is replaced, the carrier is terminated or the
   supervisor exits, the detection task must stop and release the Link reference; the Link life
   cycle must not be reversely extended by the permanent task;
8. Detection failures must distinguish carrier local overruns, send queue pressure, ACK timeout,
   peer link teardown and protocol errors, and count them separately.

The full QUIC carrier (ordinary UDP or fake-TCP outer layer) uses the carrier's own DPLPMTUD and
current `max_datagram_size()` as the source of capacity, and no longer runs duplicate application
layer PMTU probes. The bare UDP Physical carrier (including the fake-TCP outer layer) uses the
authentication application layer probe of RFC-0014; this probe can be omitted only if there is an
equivalent carrier DPLPMTUD in the future. All probes must use physical layer authentication, replay
protection and D0 priority, but must be subject to independent rate limits and cannot squeeze
forward and control flow infinitely.

The detection target can become `confirmed_capacity` or enter the LSA only after confirmation. LSA
refresh only extends the validity period of the path proof; only when the semantic value of
confirmed capacity changes, the relevant path calculation and budget update are triggered. Link must
emit local events for each semantic change of confirmed capacity:

```text
LinkCapacityChanged {
    link_instance
    direction
    confirmed_capacity
    capacity_generation
    reason
}
```

The local event of the first hop Link must directly update the send budget and snapshot of the
source node and must not wait for the LSA round trip; the remote edge is updated after the signed
LSA is accepted. The update sequence is to release the software security budget first, and then
project TUN/route asynchronously, so the capacity reduction takes effect before enqueuing in the
next frame.

The topology database and the reconcile supervisor must be distinguished:

```text
advertisement_accepted
semantic_capacity_changed
```

A new sequence, `expires_at`, or target-independent LSA update MUST not wake up Circuit reconcile
alone, nor MUST cancel a semantically equivalent OPEN attempt; `LinkCapacityChanged` only updates
the budget unless it also produces a HardRevoked or candidate availability change. Only
`capacity_generation` s strictly greater than the current value are accepted for the same
`(link_instance, direction)`; the path snapshot saves versions of the edges that make up it, and any
late local events or LSA capacity updates must not roll back the published budget.

The `capacity_generation` of the remote LSA is allocated by the topology database according to the
confirmed capacity semantic change of the directed edge; the LSA sequence is only used for LSA
freshness and replay, and may not be directly used as capacity generation. Therefore, the LSA
refresh of the same capacity will not create a new capacity version, and the old LSA that is late
after the capacity is reduced cannot overwrite the new version that has been accepted.

### 4. Reconcile actor for each destination

Each destination has the following status exclusively owned by a supervisor:

```text
NoActive
  -> Opening
  -> Stable
  -> Preparing
  -> Stable
  -> Degraded
  -> NoActive (HardRevoked)
```

State meaning:

- `NoActive`: There is no active lease available; if there is ready resolution, OPEN is started;
- `Opening`: The first Circuit is being established, or waiting for the next retry;
- `Stable`: active identity is the same as desired identity and availability is `Ready`; sending
  budget can be changed independently;
- `Preparing`: The desired identity is different from the active identity, and the old lease
  continues to be forwarded;
- `Degraded`: The target still has a valid path proof but is in `ProofStale`, or is being
  migrated, has exceeded the deadline, or the sending budget has been conservatively tightened;
  active lease continues to be restricted for forwarding. If the path proof expires, the path is
  explicitly revoked, or the authorization configuration changes, it must be converted to
  `NoActive` and cannot stay in Degraded.

Migration failure does not create the second actor. There can be at most one OPEN attempt per actor
at a time; events only update the desired resolution, and it is up to the actor to decide whether to
cancel, abandon, or continue the current attempt.

### 5. Events and generation

The following events wake up the corresponding destination actor:

- The first hop link is established, replaced or closed;
- The effective topology capacity of the selected path edge changes;
- Path proof expired or restored;
- Allowed path configuration hot loading;
- active Circuit Broken, lease expiration or sending sequence exhausted;
- retry, readiness stability and migration deadline timer.

Actors use three types of versions:

- `resolution_generation`: version of resolver observation results, used for caching and
  diagnosis;
- `attempt_id`: local submission qualification for a certain OPEN;
- `capacity_generation`: The monotonic capacity version of a single directed Link event; the
  active/desired budget uses `capacity_vector`, which is composed of multiple edge versions. It is
  not used to cancel semantically equivalent OPEN, but is only used to discard out-of-order budget
  updates.

The actor will only invalidate the current attempt if the CircuitIdentity, configuration
authorization semantics, or HardRevoked event actually changes. Simple LSA refresh, ProofStale,
proof validity extension, confirmed capacity change or unrelated topology change shall not
cancel the equivalent OPEN.

### 6. Reconcile algorithm and conditional commit

Each event handler:

1. actor gets an immutable `DesiredResolution` from resolver;
2. If `availability == HardRevoked`, first revoke the active snapshot/authorization and close the
   old send gate, and then re-execute the algorithm using the latest resolver snapshot; the
   State must not be treated as an ordinary no-candidate retry;
3. If there is no active lease, and `availability == Ready` and the desired path exists, enter
   `Opening`; if there is no Ready candidate, keep `NoActive`, and no new Circuit using expired
   path proofs shall be established;
4. If the desired identity, configuration authorization generation and active lease are the same,
   then enter `Stable` when availability is `Ready`, enter `Degraded` when it is `ProofStale`,
   and only update the sending budget; if desired is temporarily unavailable but the proof of
   active lease is still valid, enter `Degraded` and continue to use active budget;
5. If the identity or configuration authorization generations are different and the availability
   is `Ready`, record the readiness starting point; if the current active lease still has a valid
   proof, the old lease continues to be forwarded; if the desired is temporarily
   unavailable, a new readiness timer will not be started; as long as the path proof for the
   active lease is still valid, enter `Degraded` and continue to use the active budget, otherwise
   it will be processed as HardRevoked;
6. Create an OPEN with `attempt_id` after readiness continuously satisfies
   `readiness_stability_secs`;
7. OPEN uses the path, Link instance, configuration authorization algebra and current circuit
   ceiling of the attempt;
8. After receiving the OpenAck specified in RFC-0008, with matching CircuitId and valid
   signature, submit the result to the actor;
9. actor executes `commit_if_current(attempt_id, desired_identity, config_generation,
   link_instance)` within the same state lock;
10. `commit_if_current` It must also be confirmed that the actor's current desired resolution,
    configuration authorization generation, first hop Link instance, HardRevoked state and
    attempt authorization have not changed;
11. When the conditions are not met, the new Circuit is closed, waiter/authorization is cleared,
    and the results are discarded;
12. When the conditions are met, active lease, lease epoch and dataplane snapshot are replaced
    atomically. The old lease closes the data sending gate and enters drain;
13. After the drain expires, the signature Close is sent and the local and remote resources of
    the old lease are cleaned up;
14. If it fails, continue to try again according to the `deadline_secs`, with jitter backoff and
    `MigrationOverdue` rules.

`commit_if_current` is a required linearization point for this RFC. A non-atomic implementation of
reading revision independently and calling activate later is not possible. It must be executed by a
unique `LeaseRegistry`; actors can only submit intents, and `CircuitOpenManager` can only manage
waiters and attempt authorizations. `LeaseRegistry` is done in one linearization operation:

1. Compare attempt guard, target identity, configuration algebra and Link instance in
   actor/registry state;
2. Close the send gate of the old lease and invalidate the old queue entries that have not yet
   obtained permission to send;
3. Increment and publish new `lease_epoch` and dataplane snapshot;
4. Update the read-only index and authorization reference of the active lease.

`lease_epoch` must be published atomically along with the snapshot; the sending worker must not
assume that the old lease is still sendable based solely on the cached Link, key, or CircuitId in
the queue entry.

### 7. Data plane publishing and platform projection

The data plane maintains an immutable snapshot:

```text
DataplaneSnapshot {
    epoch
    routes
    active_leases
    send_budgets
}
```

Each route/lease reference must carry `lease_epoch` and `send_gate` in the corresponding destination
scope. The queue entry's qualification key is `(destination, lease_epoch)`, and you cannot just use
bare epochs that may be repeated across destinations. When replacing a snapshot, the old gate first
enters the revocation status, and then releases a new snapshot; when the sending worker holds the
gate's short-read permission, the last approved send of the old lease can be completed, and the
application layer queue items that have not yet obtained permission must be discarded. This "atomic
release" simultaneously covers selection, budget, and lease eligibility, rather than just replacing
a few pointers. The source node sends the path to read the same snapshot and completes:

- route selection;
- TCP MSS clamp;
- User IP packet size check;
- CircuitId, key and Link selection.

The new snapshot is released through an atomic replacement of memory. Kernel routes, TUN MTU, and
local policy rules are asynchronous projections of the platform layer:

- Platform update failure must not allow software to be sent beyond the snapshot's security
  budget;
- During the platform update, the old kernel route can be temporarily retained, but the new data
  must be selected by snapshot;
- The global TUN MTU is only used as a coarse-grained input boundary and is not used as the only
  security check for each destination;
- Installation, replacement, rollback, and cleanup of route handles must be implemented by the
  platform layer, with structured results reported.

### 8. Drain and resource ownership

After the new lease is released, the data plane no longer selects the old lease; the old lease only
retains a limited time for control plane close and natural emptying of datagrams that have been
handed over to the carrier. The old frames in the application layer queue do not belong to the
carrier queue and must be re-validated through `lease_epoch` and send gate. After the drain times
out, old leases must cease to be eligible to be sent, and any late queue entries must be discarded
and counted.

Resource ownership is as follows:

- actor: attempt, migration status and retry timer;
- `LeaseRegistry`: released active lease, lease epoch, send gate and active identity;
- `CircuitOpenManager`: OPEN waiter and attempt authorization; it cannot bypass the conditional
  commit the LeaseRegistry entry and issue the active lease directly;
- dataplane snapshot: route, key, link and current sending budget reference;
- relay/router: hop-by-hop binding, remote lease and relay label;
- Platform: TUN, route, policy rule and its rollback status;
- Observability: Counter accumulated by destination/logical egress, not cleared with lease.

CLOSE failure to send cannot result in permanent leakage of local resources. Closing a Link, lease
expiration, or actor exit must perform local revocation; remote resources rely on the signature
Close, Link teardown, or lease expiry as final recycling.

Configuration changes will revoke the lease only if they increment `config_generation` and affect
authorization, target identity, path constraints, or egress security semantics; display names,
metrics, and general diagnostic fields must not trigger Circuit rebuilding.

### 9. Outbound and return journeys

Circuit supervisor only manages the directions actively initiated by this node. Path capacity is
still calculated based on the actual direction of the edge, but does not assume that the return trip
uses the same path, Link instance, MTU, or proof.

If the peer needs to actively establish a circuit in the other direction to this node, it will be
parsed and managed by the peer's own destination actor. The return trip is not used as a hidden
field in the local ActiveLease, nor is it forcibly bound in both directions through a shared
fingerprint.

## Configuration and state

The configuration of RFC-0021 continues to be valid:

```yaml
path_migration:
  readiness_stability_secs: 1
  deadline_secs: 5
  drain_timeout_secs: 1
```

This RFC does not add new configuration fields. Implementations MAY add the following local state
fields:

- `active_path`,`desired_path`;
- `active_link_instance`;
- `active_config_generation`;
- `active_lease_epoch`,`send_gate_state`;
- `active_circuit_ceiling`;
- `current_send_budget`;
- `desired_resolution_generation`;
- `reconcile_state`;
- `migration_started_at`,`migration_deadline`,`migration_last_error`;
- `mtu_budget_source` (verified, conservative, or carrier-local).
- `pmtu_confirmed_capacity`, `pmtu_probe_state`, `pmtu_last_confirmed_at` of each Link;
- `pmtu_probe_successes`, `pmtu_probe_failures` and `pmtu_probe_errors` by reason.

The state field belongs to the native Unix management interface and does not enter the network
wire. `binding_id` If retained, it must be a local digest only and must not contain keys, tokens or
real traffic content; digest input should be limited to stable CircuitIdentity and must not contain
LSA sequence, expires_at or dynamic counters.

## security impact

- Relay still only forwards the opaque encrypted payload and does not decrypt the inner IP;
- Relay forwarding still must bind the current Link instance, CircuitId, authorization and lease;
- The carrier's local capacity check prevents the relay from injecting excessive DATAGRAM into the
  next hop;
- The source node sending budget can only tighten the actual verifiable capacity, and topology
  information cannot be treated as ACL or wire authentication;
- Stale OPEN results cannot obtain active lease, routing or long-term authorization;
- During the MTU drop period, the frame guard before the final transmission is a safety boundary
  and cannot be replaced by a TUN MTU update;
- PMTU probes must be protected by physical layer authentication and replay; unconfirmed probe
  targets must not increase the sending budget or write LSA;
- The probe task must be uncontrolled by Link/supervisor and cannot hold a permanent strong
  reference to a closed Link;
- The freshness of topology proof affects candidate readiness and sending budget, but does not
  directly forge or update Circuit identity;
- The full upgrade boundary of RFC-0046 means that old OPEN/control wires cannot be mixed with the
  current implementation; new Circuit control messages must not be sent to the old node until the
  upgrade is complete.

## Compatibility and migration

RFC-0046 clarifies that the current wire is incompatible with the old version, and the deployment
adopts a full upgrade: nodes in the same interconnection domain must first complete the binary
upgrade, and then enable the new OPEN, CircuitBroken, Renew and Close formats. After the upgrade,
the relay does not save OPEN's end-to-end MTU ceiling, and the source node continues to use the
local Circuit ceiling with dynamic send budget; `DatagramTooLarge`, forward drop, MTU budget, and
migration failure count should be observed.

## Testing and Acceptance

### Unit and model testing

- Same as `CircuitIdentity` but when LSA sequence, expires_at or irrelevant topology generation
  changes, OPEN will not be canceled and Circuit will not be rebuilt;
- When the path, candidate priority or first-hop Link instance changes, a new reconciliation
  attempt is generated;
- `OpenFingerprint` The rebind of the same OPEN idempotent with different CircuitId, path, public
  key or temporary public key is rejected, but Forward does not read the end-to-end capacity of
  the source node as the relay ceiling;
- `commit_if_current` rejects the outdated attempt and does not replace the active lease;
- Concurrent events at the same destination can only produce one actor and one OPEN attempt;
- When the configuration authorization generation changes, the target public key changes, or
  HardRevoked is interleaved with OpenAck, old attempts must not be submitted as active;
- State conversion of `path == None`, proof expired, active lease exists and active lease does
  not exist;
- The capacity change of the desired path during `Preparing` will not change the budget of the
  active path; it will be switched to the desired budget after the new lease is submitted;
- Out-of-order `capacity_generation` events will not roll back the active or desired budget;
- The PMTU state machine maintains correct boundaries when confirming rising, single failure,
  continuous failure, repeated detection and link cancellation;
- PMTU rises and multiplexes the historical confirmed/lower bound, and does not re-complete the
  two points from the conservative initial value in each round;
- PMTU decline can reduce confirmed capacity within a short failure window without waiting for a
  long period timer;
- ACKs that are late or belong to old probes shall not update the current PMTU state;
- An increase in MTU only increases the budget or record upgradeable status and does not trigger
  circuit rebuilding;
- An MTU drop immediately reduces the budget, and oversized frames in the old queue are rejected
  before they are finally sent;
- When snapshot replacement, drain timeout and old application layer queue are interleaved, the
  lease epoch/send gate prevents old frames from being sent; datagrams that have been handed over
  to the carrier can still be completed according to drain rules;
- The counter accumulates continuously before and after lease migration;
- drain, Close failure, Link teardown, actor exit, and lease expiry all clean up local resources.

### Carrier and relay testing

- QUIC, bare UDP, and fake-TCP's `send_physical` all reject frames that exceed the current local
  wire capacity;
- QUIC uses carrier/Quinn's DPLPMTUD without additionally starting the repeated application layer
  probe;
- Bare UDP/QUICP probe has solo, deadline, rate limiting, retry and cancellation behaviors;
- After the Link is closed, the PMTU task exits and the old Link can be released;
- The relay does not reject larger frames that the current carrier can send due to the smaller
  local end-to-end capacity of the source node;
- The relay only discards and counts `DatagramTooLarge` and does not close irrelevant Links or
  Circuits;
- The relay's wire length pre-check occurs before priority admission, physical seal and sequence
  number allocation, and correctly distinguishes the outer headers of QUIC and bare UDP/fake-TCP;
- When the capacity of the carrier changes after pre-checking, the final `DatagramTooLarge` only
  discards the current frame and counts, and does not trigger Link/CircuitBroken;
- After the downstream carrier MTU changes, there is no need to re-OPEN, and the relay sends or
  rejects according to the new capacity;
- relay still rejects errors Link instance, unknown CircuitId, no authorization and expired lease.

### Integration testing

- When the fallback is established first, the relay is preferred and then restored, it will be
  migrated to the preferred path within the deadline;
- During the LSA periodic refresh period, a single circuit is maintained, and periodic OPEN storms
  do not occur;
- LSA periodic refresh only updates the proof validity period and does not trigger
  reconciliation of paths whose capacity has not changed;
- There is no need to wait for LSA when the local first-hop Link confirmed capacity decreases, and
  the snapshot budget is tightened immediately;
- The relevant path budget will be updated only when the confirmed capacity changes, and no
  circuit reconstruction will occur;
- Neither the rise nor fall of the preferred path MTU triggers Circuit rebuilding;
- `tests/remote_rfc0022_dynamic_budget.sh` Dynamically tighten and restore the first-hop MTU in
  the three-node namespace, verify that the local capacity event updates the active path budget,
  and the number of Circuit OPEN times and active path remain unchanged; the namespace prefix and
  host veth name are both isolated according to CI run.
- `tests/remote_reconnect_path_switch.sh` Verify the A-B-D preferred path and A-C-D backup path in
  the four-node namespace: After a short-term stop and restart of B, both ends switch to the
  backup path and restore the preferred path; after a long-term stop of B exceeds the idle
  timeout, the backup path continues to carry bidirectional TUN traffic, and after B recovers,
  both ends migrate back to the preferred path again; the test also checks the active path,
  healthy state and bidirectional ping of both ends of A/D.
- When topology/link/config events arrive staggered during OPEN, OpenAck, Close and drain, the
  final active identity only corresponds to the latest desired identity;
- The test covers three-node paths, downstream MTU changes, relay over-limit drop count and
  service recovery;
- Complete `cargo fmt --check`, Strict Clippy, `cargo test`, and run remote preferred path
  migration, PMTU/MSS, and three-node tests on demand;
- After the real network test, confirm that TUN, route, namespace, firewall and temporary
  resources have been cleared.

## Open Questions

- Whether to add end-to-end tunnel fragmentation/reassembly in subsequent RFCs to avoid super-MTU
  frame discarding during topology propagation delays;
- Whether background circuit upgrade based on throughput revenue is required, as well as the
  minimum revenue threshold and cooling time for upgrade;
- Whether to permanently fix the global TUN MTU to the configured value and rely solely on the
  per-route software budget;
- Does relay `DatagramTooLarge` need to be fed back to the source node through existing reliable
  control flow, or only rely on topology LSA and local indicators;
- Number of consecutive successes required for PMTU to rise, fall failure window, hysteresis,
  minimum detection increment and cool down time;
- Whether it is necessary to expose a unified PMTU probe reason enumeration for different
  carriers;
- Whether to additionally expose `relay_forwarding_mode` (current-carrier or binding-ceiling) for
  observation; this field does not enter the wire and does not change the conservative
  compatibility policy of hybrid deployments.

## implement plan

1. Set the resolver output convergence as `ResolvedPath`/`DesiredResolution`, and define stable
   `CircuitIdentity`, availability reason and per-path `capacity_generation`;
2. Introduce a single actor for each destination and unify configuration, Link, topology, timer
   and OPEN result events;
3. Implement unique `LeaseRegistry`, `attempt_id` and in-lock `commit_if_current` to replace the
   current scattered active path/MTU judgment;
4. Incorporate `ActiveLease`, route reference, and current send budget into immutable dataplane
   snapshot;
5. Implement PMTU state with history boundaries, hysteresis, fast descent, deadline and
   cancellation for bare UDP/QUICP; QUIC directly consumes carrier/Quinn's DPLPMTUD results;
6. Let PMTU publish only confirmed capacity and separate `advertisement_accepted` from
   `semantic_capacity_changed`;
7. Separate the relay's OpenFingerprint and RelayForwardBinding; let the relay forwarding only
   call the next hop `send_physical`, and remove the permanent constraints of the end-to-end MTU
   on the relay label life cycle;
8. Let the source node check the current send budget before data is queued and finally sent;
9. Add lease epoch/send gate to the application layer queue and define the drain boundary between
   the old queue entry and the carrier queue;
10. Retain the path migration stability, deadline, drain and state fields of RFC-0021, and
    delete the MTU special judgment;
11. After accepting this RFC, the PMTU/relay binding semantics of RFC-0014, RFC-0018 and
    `docs/protocol.md` will be updated synchronously;
12. After completing the model, carrier, three-node and real network acceptance of this RFC,
    update the state to `Implemented`.

## Implementation Notes

- `src/reconcile.rs` provides I/O-free `CircuitIdentity`, `ResolvedPath`, `DesiredResolution`,
  availability, `CapacityVector` and reconcile state models; the resolver outputs the confirmation
  capacity of each directed edge and `capacity_generation`.
- `CircuitOpenManager` assumes the only active-lease registry: OPEN attempt with destination,
  identity, configuration algebra, Link instance and monotonic attempt id; `commit_if_current`
  closes the old gate, increments the lease epoch and issues a new budget after verifying the
  desired guard, authorization and attempt within the lock.
- The active route uses shared send gate, lease epoch and budget; the application layer team
  rejects expired leases and frames outside the current capacity before enqueuing the queue and
  finally calling carrier. Capacity reduction will not trigger Circuit reconstruction.
- The route snapshot refresh updates the budget according to the `(destination, circuit_id, path,
  Link instance)` condition, and copies the CircuitId, key, epoch, and gate from the same active
  lease snapshot to avoid splicing the old route fields with the new lease when migration is
  staggered.
- The relay label no longer saves the end-to-end MTU of OPEN; `send_physical` is pre-checked
  according to the actual wire length of QUIC or bare carrier before priority admission, physical
  seal and sequence number allocation, and an authoritative check is still performed for final
  transmission.
- Bare UDP/fake-TCP PMTU uses historical upper and lower bounds, continuous successful
  confirmation, fast drop check, probe deadline, solo attempt and Link cancellation; full QUIC
  directly consumes Quinn's application DATAGRAM upper limit. Topology allocates an independent
  generation for directed capacity changes, and LSA refresh does not create capacity versions;
  PMTU failures are counted according to local overlimit, queue pressure, ACK timeout, peer
  teardown, and protocol errors respectively.
- QUIC Link polls Quinn's current DATAGRAM upper limit through a weak reference background monitor
  and publishes capacity events; the bare carrier publishes the same type of events after being
  confirmed by the probe. Link directly updates the budget of the first-hop active lease through
  the local `LinkCapacityChanged` event; the remote capacity still enters the capacity vector
  after the signed LSA is accepted. The capacity vector requires the edge set to be consistent
  with the active path, and rejects out-of-order or same-version conflict updates by generation;
  the routing snapshot only publishes paths that completely match the active identity.
- The carrier performs side-effect-free wire-size preflight before priority admission, seal, and
  physical sequence number allocation, and retains authority checks at the final sender; wire
  overruns, queue backpressure, and protocol errors are counted separately, and relay continues to
  serve subsequent frames for a single overrun or backpressure frame.
- Proof loss, Link instance shutdown and stale OpenAck will all close the gate, revoke the local
  active lease, and try their best to clean up remote resources; the same destination still
  maintains a single worker/single OPEN attempt.
- The destination resolver only publishes the complete `ResolvedPath` of the first ready
  candidate, which also contains the first hop Link instance, proof validity period and capacity
  vector; OPEN worker and desired guard use the same result, and the route projector only consumes
  the active lease and no longer reselects the path.
- Migration readiness uses the complete `CircuitIdentity` as the key, and capacity changes will
  not reset the stability window; ensure requests triggered by the TUN health route are
  deduplicated by destination within `CircuitOpenManager`, and unbounded channels are not used.
- Covered resolver/identity, capacity version, stale commit, budget tightening, relay wire
  overhead, existing three-node opaque forwarding, as well as `cargo fmt --check`, strict Clippy
  and `cargo test`.
- Added `tests/remote_rfc0022_dynamic_budget.sh`: Use three-node isolation namespace, dynamically
  modify A-B veth MTU, verify that active path and OPEN times remain unchanged during
  drop/recovery, and capacity budget is synchronized.
- Added `tests/remote_reconnect_path_switch.sh`: Using four nodes and two explicit multi-hop
  paths, covering relay short-term restart and long-term offline/reconnection beyond idle timeout,
  verify that the preferred/backup path is switched consistently at both ends of A/D, and
  namespace, TUN, routing and temporary sockets are uniformly cleaned up at the end of the test.
