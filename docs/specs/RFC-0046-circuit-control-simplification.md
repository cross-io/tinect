# RFC-0046 Circuit control plane simplification and long lease state convergence

- Number: RFC-0046
- Title: Circuit control plane simplification and long lease state convergence
- Status: Implemented
- Created: 2026-08-27
- Last updated: 2026-08-29
- Change record: When a migration candidate OPEN fails due to local control admission
  backpressure, the unified Renew/grace check of the old active circuit must still be performed;
  only non-local admission errors are counted as candidate path failures.

## Background and Problem

The current Circuit control message carries `CircuitId`, Open nonce, path, TTL and path MTU hints at
the same time. Part of the signature transcript does not include the message type, resulting in
different control messages possibly reinterpreting each other when the field values   are the same.
`CircuitBroken` and the historical `CircuitNoSession` respectively bear similar failure feedback
semantics. On the other hand, long lease, DATA refresh and periodic Renew co-exist, but the
instantaneous failure of Renew will prematurely cancel the active circuit and increase the agent
delay.

## Target

1. Use `CircuitId` as the unique token for a single Circuit attempt to reduce duplicate binding
   fields.
2. All signature control messages use field separation transcripts containing wire kind.
3. Simplified OPEN: The identity is derived from the signing public key, and the destination node
   is derived from the end of the path; the TTL that cannot be safely decremented by end-to-end
   signatures and the path MTU field that is only a hint are deleted.
4. Merge the processing path of existing Circuit failure feedback, while retaining the
   reachability of unknown sessions without nonce and the `(first-hop Link instance, CircuitId)`
   match on the source side.
5. Keep the circuit lease and authenticated DATA refreshed for a long time; Renew is a
   low-latency confirmation/detection, and the active circuit should not be revoked directly in
   case of short-term failure. Explicit remote rejection immediately fails feedback; if Renew,
   ACK and feedback are lost, the source is bounded to withdraw after a complete long lease
   failure grace, avoiding permanent black holes without sacrificing the long lease delay
   benefits of the normal path.
6. Keep Topology Snapshot/Delta, ACK, Request and fragmentation protocols, and only convert
   sending and receiving state convergence to verifiable explicit state machines.
7. Adaptive FEC repair rate, credit, tail repair and recovery probe based on contralateral
   reporting are intact.

## Non-goals

- This RFC does not change DATA, Physical framing, end-to-end encryption, or FEC codec formats.
- This RFC does not change topology synchronization to snapshot-only.
- This RFC does not introduce a fixed repair rate, nor does it remove `FecReport`.
- This RFC does not require compatibility with older versions of wire; deployment requires full
  upgrade.

## Terminology and state

`Circuit token` refers to `CircuitId` and its first-hop Link instance. `Active` indicates that the
binding is still allowed to be used by the data plane locally; `RenewPending` only indicates that
confirmation is waiting and does not change the Active state; `Invalidated` indicates the final
revocation triggered by explicit or lease.

## design

### Signature domain separation

The first field of the transcript of each signature control message is its wire kind, followed by
the fields of the message and the signature public key. `OpenAck`, `OpenReject`, `Renew`,
`RenewAck`, `Close`, `CircuitBroken` must use independent kind. The signature public key must still
be consistent with the identity check of the direct sender/forwarder; the forwarding node re-signs
and does not forward the original signature to impersonate itself.

### OPEN and token

OPEN retains `CircuitId`, temporary X25519 public key, source public key, ordered path and
signature. `source` is deduced from the public key, and `destination` is the last node of path. Each
daemon must not reuse CircuitIds that may still be reached on its own first-hop Link instance;
feedback from old tokens must be idempotent ignored. Relay only selects the next hop based on the
current node in path and does not modify the signature content.

### Failure feedback

A unified invalidation reason is used internally to handle CircuitBroken: invalidation of existing
binding, unknown receiver session, missing relay label, and Renew rejection of deleted/unmatched
bindings only rely on CircuitId and reason, and do not require that the recycled binding still
exists. Renew refuses to use `CIRCUIT_RENEW_REJECTED_REASON` and is signed back by the node that
rejected the Renew. It must go through direct Link peer authentication, hop-by-hop re-signing, and
source-side token matching; failure to send feedback cannot block local recycling. Source failure
grace, lease, and Link health status are jointly responsible for the final convergence.

### Long lease and Renew

`CIRCUIT_LEASE` continues to use the current long value, and authentication DATA continues to
refresh the relay binding. The source sends Renew periodically, but if Renew times out, control flow
admission is rejected, or ACK is lost, only `RenewPending` will be recorded and the active circuit
will continue to be used; the first consecutive failure starts a local failure grace equal to the
current `CIRCUIT_LEASE`; the grace record is bound to the current `CircuitId` and `lease_epoch`, and
the subsequent successful RenewAck with an exact matching counter can clear this grace. Only when
`CircuitBroken`, Link instance is shut down, or local failure grace/lease deadline expires will the
binding be revoked and rebuild triggered. Renew waiter saves the expected counter. Late or repeated
old RenewAck can only be ignored and cannot complete the next Renew. Renew for the same counter must
repeat the ACK, older counter idempotent is ignored. In this way, bounded convergence is still
bounded when feedback is completely lost, but the short-term failure of normal Renew will not
shorten the long lease. Grace expires using a unified hard-revoke process, clearing active,
authorization, session, return-flow and Circuit DNS state, and sending CircuitClose with
best-effort.

During migration, if candidate OPEN fails to be sent or OpenReject is caused by local control
admission backpressure, the Renew/grace keepalive path of the current active circuit must be called
first; local admission only skips candidate path failure accounting and migration failure markers,
and cannot skip the renewal of the old lease. In this way, when the candidate control plane is
congested, the old path still has a long lease and bounded failure grace convergence.

### topology synchronization

Snapshot and Delta wire remain unchanged. Each Link uses a single synchronization controller to
maintain the sending direction and receiving direction respectively: the sending direction
experiences `NeedSnapshot -> Sending -> AwaitingAck -> Synchronized`, and the receiving direction
experiences `AwaitingInitial -> Assembling -> Applying -> Synchronized`. `TopologyReady` is only
allowed if both directions are synchronized. Fragments receive idempotent repeatedly; ACK is only
sent after atomic apply is successful; timeout, conflict, or budget exhaustion enter recovery, merge
duplicate requests, and do not reset the snapshot being sent.

## Security and Compatibility impact

Adding kind prevents signature reinterpretation across message types. Delete duplicate fields of
source/destination to reduce inconsistent input; source must be deduced from the signature public
key, and path must be non-empty and include the current node. After deleting TTL, there is no longer
reliance on the end-to-end field that cannot be safely decremented, and the upper limit of path
length and link-level hop verification assume boundary control. This change is not compatible with
old wires, and it must be ensured that the new format is not sent to old nodes during the upgrade.

## Testing and Acceptance

- Encoding and decoding, signature kind exchange, wrong public key, replay,
  duplicate/late/out-of-order feedback testing.
- DATA can still be sent under Renew timeout under long leases; explicit failure, link
  replacement, downstream restart, and local failure grace/real lease expiration are eventually
  revoked and rebuilt, and still bounded when feedback is completely lost.
- The lateness, duplication and counter reordering of RenewAck cannot satisfy the wrong waiter;
  the old grace cannot be inherited after CircuitId or `lease_epoch` replacement.
- Failure grace expiration must complete the same local cleanup as hard-revoke and best-effort
  send CircuitClose.
- When the local admission continues to reject the migration candidate, it will still try to renew
  the old active circuit and perform a complete revocation after the failure grace expires,
  instead of letting the remote lease expire silently.
- Multi-hop relay feedback hop-by-hop authentication, lost and duplicate ACK bounded convergence.
- Snapshot/Delta fragment reordering, duplication, conflict, lost ACK, link replacement and
  recovery budget testing.
- Preservation and regression of contralateral FecReport driven repair rate adaptive, credit, tail
  repair and recovery probe tests.
- CI must cover direct path, multi-hop relay, control plane congestion/packet loss, downstream
  restart and link replacement.

## Implementation Notes

- 2026-08-27: Complete implementation and acceptance. Control messages are separated using kind
  fields, OPEN deletes wire TTL, path MTU, source/destination duplicate fields and nonce;
  CircuitId and first-hop Link instance are used as source associated tokens; CircuitBroken merges
  unknown session, relay label, Renew binding rejection and downstream failure feedback. The long
  lease is retained, Renew fails instantaneously and enters pending and starts the local failure
  grace bound to `CircuitId + lease_epoch`, which is equal to the long lease; Renew waiter
  verifies the accurate counter, and the old ACK cannot complete the new lease renewal; when
  feedback, ACK and Renew are all lost, the grace expires through a complete hard-revoke to clean
  up the active, session, return-flow, Circuit DNS and authorization, and then revoke the active
  lease. Topology Snapshot/Delta uses an independent bidirectional state machine to send and
  receive state, and performs bounded convergence on repeated fragments, lost ACKs, repeated
  Requests and out-of-order feedback; the inbound synchronized flag will be restored after the
  retransmission ACK of the completed Snapshot is successful, and the fragment count changes will
  be rejected before index access. Adaptive FEC repair rate, credit, tail repair, recovery probe
  and FecReport are unchanged. 2026-08-28: The local control admission of the migration candidate
  OPEN refuses to still perform the Renew/grace keepalive of the old active circuit; the local
  admission no longer skips the renewal of long leases, and does not count candidate path
  failures. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-features` passed; privileged CI scenarios cover Circuit feedback, Link
  replacement, multi-hop control plane congestion, 35% packet loss/500ms delay and recovery after
  sustained D2 flooding.
- 2026-08-28: Fix CircuitOpenManager's lock order reversal between OPEN submission and Link
  teardown, and allow domain name routing candidates to enter the same Circuit resolution
  admission as prefix routing; the fast closing path of outbound links is now synchronously
  cleared return-flow status to avoid continuing to point to closed links during reconnection.
- 2026-08-28: OPEN ACK first releases the corresponding Link authorization under the authorization
  lock, and then wakes up the source waiter; if the waiter has been canceled, the authorization is
  rolled back to avoid the worker observing the ACK but submitting it before the authorization.
  Added ACK release order and return-flow cipher to clean up regression tests.
- 2026-08-28: Discard ACK when the Link token expires after the waiter is removed; cancel the
  unfinished OPEN attempt and revoke its temporary authorization to avoid ACK/timeout interleaving
  and leaving stale authorization. Add corresponding race test.
- 2026-08-28: The OPEN waiter record belongs to the attempt; ACK is issued in the order of `slots
  -> authorized_links` to reconfirm that the attempt is still the current attempt. In this way, no
  matter which party linearizes cancellation and late ACK first, authorization will not be issued
  for the canceled OPEN; a new late ACK rejection test is added.
- 2026-08-29: Review and fix: The topology Delta receiving threshold only retains the RX state
  machine condition, and no longer requires that the outbound Snapshot has been ACKed (the
  outbound ACK and the peer Delta follow a different uni stream, and the completion order is not
  guaranteed. The original condition will falsely trigger recovery when the ACK is late and
  consume the peer recovery budget); enter `SnapshotRequired` when the Delta outbox is full: clear
  the old Delta, mark it as unsynchronized, and send recovery to the peer. Request, recovery The
  Link is closed when the Request cannot be delivered, and if the receiving path is still not
  synchronized after applying the peer recovery Snapshot, if the local end is still outbound, it
  will be re-fixed and the local Snapshot will be sent to restore bounded convergence in both
  directions; `MAX_INFLIGHT_TOPOLOGY_SNAPSHOTS` dead code is removed (single assembly slot is
  guaranteed by the construction); `next_topology_sync_id` no longer panics when it overflows. In
  addition, the Renew old counter was changed from "forward and ACK" to idempotent ignore
  (`StaleRenewal`), and the reason code fed back by CircuitBroken (Link closed = 1, relay failed
  to forward = 7) was named constant with the OpenReject universal rejection code (1).
