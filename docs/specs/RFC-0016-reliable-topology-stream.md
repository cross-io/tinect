# RFC-0016: reliable-topology-stream

- Number: RFC-0016
- Title: reliable-topology-stream
- Status: Implemented
- Created: 2026-07-27
- Last updated: 2026-08-29
- Change record: 2026-07-30 Clarified that Topology is completely migrated to reliable control
  stream; removed Physical DATAGRAM Topology payload; clarified Snapshot atomic submission,
  Snapshot recovery after Delta failure, bounded resources and RFC-0017 scheduling dependencies.

> RFC-0037 Description: The wire position of the historical field name `datagram_mtu` in this
  article remains unchanged, and the current semantics is `inner_mtu`, which is the complete user
  IP packet capacity; the carrier-local Physical/QUIC capacity is only converted at the Link
  boundary and does not directly enter the LSA.
2026-07-30 Clarify bidirectional Link epoch, Snapshot ACK/Request, TopologySync capability
negotiation, neighbor resource upper limit and LSA expiration processing. 2026-07-31 Corrected the
ACK timeout recovery direction, added Snapshot retention and recovery slot, canceled the old
protocol downgrade in this RFC; supplemented the LSA size limit, Snapshot recovery budget, and moved
the creation timing of the RFC-0017 arbiter forward to the connection life cycle to cover
Hello/HelloAck. Fixed Snapshot ACK timeout and control stream's full frame length boundary.
2026-07-31 Add long-term running activity constraints: clarify reconnection responsibilities, LSA
reliable renewal, TopologyReady threshold, and recovery acceptance after long-term network faults
are eliminated. 2026-07-31 Implement reliable topology stream, bidirectional Snapshot/ACK, resource
upper limit, TopologyReady routing gating and recoverable reconnection; verify circuit recovery
after restart of egress, relay and source nodes in an isolated three-node network. 2026-07-31 Fixed
the reconcile race condition between paths hot reload and existing circuit workers: reload must wake
up. The destination worker that has been waiting for topology or OPEN retry cannot miss new
configurations due to single worker deduplication. 2026-08-15 The unit of the LSA capacity field is
changed to `UserIpCapacity` according to RFC-0037. 2026-07-31 Fixed the Physical liveness sequence
during reconnection: Maintenance Ping must not block the authentication Physical keepalive of the
idle Link, otherwise the control stream backpressure will cause an incorrect idle timeout.
2026-08-28 Clarified that Snapshot recovery is invalid according to the sending/receiving direction;
repeated sending of submitted Snapshot must be restored at the same time after the ACK is
successful, and the inbound flag of the receiving state machine and carrier cannot be cleared in
the other direction. 2026-08-28 Clear recovery Request cannot be written through local admission or
control stream. The current Link epoch must be closed, and a new epoch must be established by the
party responsible for reconnection. The recovery status cannot be left on the old connection without
persistent retry. 2026-08-28 Clarify that when active Snapshot receives a Request while waiting for
ACK, it must not clear the subsequent Delta; the old unfinished assembly will be eliminated
immediately after the new `sync_id` is accepted to avoid the old timeout triggering recovery again.
2026-08-28 Increase the bounded superseded Snapshot ID window; late fragments of eliminated
Snapshots must be ignored, and the assembly of new Snapshots cannot be cleared or recovery triggered
again. 2026-08-28 Added RX Snapshot generation watermark; it records the maximum generation that has
been observed in the current Link epoch. Snapshots below this watermark must be discarded in the
reception phase even if they exceed the completed ID window; old completed Snapshots can only resend
ACKs and cannot recover across the observed update generation `Synchronized`. 2026-08-29 The Delta
reception threshold only relies on the RX state machine, and no longer requires that the outbound
Snapshot has been ACKed (the outbound ACK follows a different uni stream from the peer Delta, and
the completion order is not guaranteed. The original condition will be false when the ACK is late,
triggering recovery and consuming the peer recovery budget); when the Delta outbox is full, it
enters `SnapshotRequired`: clear the old Delta, mark it as unsynchronized, and send a recovery
request to the peer. Recover Request The Link is closed only when it cannot be delivered; after
applying the peer recovery Snapshot to the receiving path, if the local end is still not
synchronized outbound, it will be re-fixed and the local Snapshot will be sent to ensure
bounded convergence recovery in both directions. 2026-08-09 RFC-0027 Removed hot reload; the
constraints in this RFC on path hot reload triggering reconcile no longer apply, and the
configuration change is changed to a complete restart.

## Background and Problem

The current implementation puts `LinkStateAdvertisement` (LSA) into the Physical `Topology` payload,
carried via QUIC DATAGRAM, bare UDP, or fake-TCP. Physical AEAD can authenticate and protect these
payloads, but DATAGRAM itself does not provide retransmission, ordering, or delivery guarantees.

The current protocol relies on periodic snapshot convergence: nodes send a batch of currently known
LSAs approximately every `keepalive_secs`, and the LSAs are deduplicated and expired through origin
signature, origin sequence and `expires_at`. This model can tolerate occasional packet loss, but it
will cause the following problems:

1. After a new Link is established, it must wait for the next cycle before receiving the complete
   topology.
2. The propagation delay of topology changes is affected by at least one keepalive period.
3. A batch of LSAs share a DATAGRAM; any packet loss will cause the status update of the entire
   batch to fail.
4. When the topology scale approaches the upper limit of DATAGRAM, a single batch can only carry
   part of the state.
5. Continuous packet loss, brief congestion, or link reconstruction may cause some nodes to
   discover that the topology is no longer updated until the LSA TTL expires.

The topology change itself belongs to the control status and cannot rely on the discardable DATAGRAM
transmission. All Snapshots and Deltas must be delivered via reliable streams; periodic Physical
refresh is no longer defined.

Canceling a physical refresh does not cancel the LSA's TTL renewal. Even if the adjacency set does
not change, the origin must still generate a complete LSA with a higher sequence and new
`expires_at` before the old LSA expires, and propagate it according to the Reliable Delta rules of
this RFC; otherwise the stable topology will error out after the TTL expires.

This RFC defines a reliable topology synchronization model: a reliable stream is responsible for the
initial Snapshot and all deltas. The correctness of Topology changes only relies on Reliable
Snapshot and Reliable Delta. All messages use the same set of LSA encoding, signature, sequence,
expiration and validation rules.

## Goals and Non-goals

### Target

- After the new Link is established, the initial synchronization of the topology will be completed
  as soon as possible.
- Topology changes are propagated in a timely manner through reliable streams.
- Allow topology snapshots to exceed the capacity limit of a single control message.
- Define deterministic behavior for duplication, reordering, reconnection, stream interruption,
  expired and incomplete snapshots.
- The origin signature, origin sequence, TTL and topology routing semantics of LSA are not
  changed.
- Prevent non-authoritative, incomplete views of neighbors from deleting LSAs from other local
  sources.

### Non-goals

- Do not turn the topology database into an authoritative copy of a single neighbor.
- Does not change the wire field or signature input of `LinkStateAdvertisement`.
- Do not allow Topology to host Circuit, DATA, or PMTU Probes.
- Does not extend QUIC stream reliability to the bare UDP data plane; this RFC only specifies the
  Topology control plane.
- Topology database persistence across daemon restarts is not introduced.

## the term

- **LSA**: `LinkStateAdvertisement`, signed by the origin node and with origin sequence and link
  State record of `expires_at`.
- **LSA TTL**: The validity period from the time of LSA generation to its `expires_at`; the
  implementation uses the currently effective TTL constants or configuration values. This article
  does not create new independent configuration items.
- **Topology Delta**: One or more reliable notifications of new LSAs, does not represent a
  complete database; each Accepted topology change must eventually enter a reliable delta or
  subsequent Reliable Snapshot.
- **Topology Snapshot**: A collection of LSAs currently known to the sender that have not expired
  at the time of sending.
- **Reliable Sync**: Snapshot or Delta sent via QUIC one-way control stream.
- **Sync ID**: The local sending direction and Link epoch range identifier of a Snapshot
  transmission, used for splicing fragments.
- **Link epoch**: The life cycle of a QUIC/authentication Link. After the Link is reconnected, the
  unfinished Snapshot of the old epoch shall not continue to affect the new Link.
- **SnapshotRequired**: The Link's Reliable Delta send or receive cannot guarantee continued
  convergence, and the old Delta must be paused and a new full Snapshot's recovery status must be
  queued.
- **TopologyReady**: The current epoch of the Link has completed the verification and submission
  of the inbound initial Snapshot, and the local initial Snapshot has received a matching ACK;
  only this state can regard the missing topology of the Link as synchronized. You must exit the
  State after entering `SnapshotRequired`; you can only re-enter after restoring the Snapshot and
  meeting the same bidirectional conditions again.
- **Reconnect owner**: For each expected long-term adjacency, the end responsible for continuing
  to initiate new connections after the Link is closed. Each such adjacency must have at least one
  explicit party responsible for reconnection.

## Design overview

Each authenticated Link uses the following propagation strategy:

```text
Link established
├─ A→B Reliable Snapshot: Send a complete snapshot of the current topology
└─ B→A Reliable Snapshot: Send a complete snapshot of the current topology

topology changes
└─ Reliable Delta: Send newly accepted LSA

Reliable stream interruption or Link reconstruction
└─ New Link epoch resends full Snapshot

Stable operation
└─ origin can reliably renew the LSA before the TTL expires; unchanged adjacencies cannot stop propagating
```

All LSAs in Reliable Sync enter the same `Topology::apply` authentication and deduplication path.
The receiver must verify the LSA signature, origin, and sequence, and cannot skip LSA level
verification just because the message comes from a reliable stream. Snapshot must complete the
decoding, structure, signature and origin verification of the entire batch before submission;
`expires_at` is checked during actual apply, and `Topology::apply` is only allowed to be called
after pre-verification is completed.

## Reliable Sync Protocol

### Control message type

Add after existing control message types:

```text
25 = TopologySync
26 = TopologySyncAck
27 = TopologySyncRequest
```

The control message outer layer remains in the existing format:

```text
kind:u8 | body_length:u16(be) | body
```

Each control message is sent over a separate QUIC uni stream, with stream EOF indicating the end of
the message. The existing `u16` body limit for control messages still applies. TopologySync's full
encoded message can be `u16::MAX + 3` bytes (`kind` and `body_length` total 3 bytes in the outer
layer); its dedicated receive path must be capped at `read_to_end` by this value. The old control
receive path that only allowed reading of `u16::MAX` complete bytes MUST NOT be reused, nor may
legitimate messages with body exactly `u16::MAX` be rejected as a result.

`TopologySyncAck` and `TopologySyncRequest` also belong to S1 and must undergo local stream
admission according to RFC-0017. ACK only indicates that the specified Snapshot has completed
decoding, verification, and submission, and does not indicate any topology deletion operation.

`TopologySyncAck` body:

```text
sync_id:u64
```

`TopologySyncRequest` body:

```text
reason:u16
```

`TopologySyncRequest` always requests the sender's latest complete Snapshot of the current Link
epoch; the receiver does not request replay of an old `sync_id`. Unknown reason must remain as a
loggable error, but cannot bypass full Snapshot recovery.

To complete capability negotiation, Hello and HelloAck bodies are added after `sender_receive_id`
and before signature:

```text
capabilities:u32
```

This RFC assigns bit `0` to `reliable_topology_stream`. This field must be incorporated into the
existing signature input for Hello/HelloAck; enabling kind 25, 26, 27 is only allowed if both
parties' capabilities are set to bit `0`. Unrecognized capability bits MUST be ignored and
forwarding compatibility preserved.

### TopologySync body

```text
mode:u8
sync_id:u64
chunk_index:u16
chunk_count:u16
lsa_count:u16
lsa[lsa_count]
```

Field requirements:

- `mode = 0x00`:Snapshot.
- `mode = 0x01`:Delta.
- Other modes must be rejected.
- Snapshot's `sync_id` is unique within the current Link epoch; the sender is not allowed to reuse
  the same ID concurrently.
- The sender uses a monotonic counter without wrapping during the process life cycle to allocate
  `sync_id`; the receiver only compares the Snapshot generation within the current Link epoch, and
  discards the comparison state after the Link epoch ends.
- Delta's `sync_id` can be the monotonic notification Number within the sender's current Link
  epoch; Delta does not need to be spliced   into a complete snapshot.
- `chunk_count` must be greater than 0.
- `chunk_index < chunk_count`.
- All chunks of a Snapshot must have the same `sync_id`, `chunk_count`, and `mode`.
- Delta's `chunk_count` must be 1 and `chunk_index` must be 0.
- `lsa_count` can be 0; an empty Snapshot indicates that the sender currently has no unexpired
  LSAs.

Each message must satisfy:

```text
3 + body_length <= 65538
```

Actual implementations must calculate capacity using the current LSA wire encoding and must not
assume that LSAs are fixed length. A single TopologySync message must not exceed the `u16::MAX` body
limit of the existing control stream.

### Snapshot Sharding

When a complete Snapshot cannot fit into a control message, the sender must split it into multiple
chunks. The sender should fix the LSA set and `sync_id` when generating Snapshot, and cannot re-read
the database during fragment sending, otherwise different chunks may come from different time
points.

The receiver will submit the Snapshot as a sync batch only after receiving all `chunk_index`. The
encoding, structure, signature, and origin of all LSAs in the batch must be decoded and verified
before submission; if any check fails, the entire unsubmitted Snapshot must be discarded.
`expires_at` is rechecked when each LSA is actually applied; LSAs that have expired during
reassembly are ignored and other still valid LSAs should not be discarded as a result. After all
verifications are successful, the existing `Topology::apply` logic will be called one by one; the
LSA of the old sequence will be ignored according to the existing replay rules. After the Snapshot
is submitted, path recalculation is triggered at most once and `TopologySyncAck` is sent.

Snapshot does not have delete semantics:

- LSAs present in the Snapshot are verified and attempted to be installed or refreshed.
- LSAs missing from the Snapshot MUST NOT be immediately deleted from the receiver database as a
  result.
- LSAs can still only be expired via `expires_at`, or removed by existing explicit database
  lifecycle logic.

This is necessary because the neighbor's Snapshot is only the view known to the neighbor at that
time and does not necessarily include the state received by this node from other neighbors.

### Snapshot receives state and boundaries

The receiver must set limited Snapshot reassembly resources for each Link epoch:

- The number of outstanding Snapshots retained at the same time must be capped;
- There must be an upper limit on the cumulative number of bytes of unfinished Snapshots;
- `chunk_count` must have an upper limit;
- `lsa_count` of any chunk must have an upper limit;
- Reject the Snapshot when it exceeds any upper limit and release its cached chunks;
- MUST NOT allocate unbounded memory due to the remote sending an arbitrarily large `chunk_count`
  or `sync_id`.

This RFC specifies the following default upper bounds; implementations MAY use these values   via
compile-time constants, but MUST not be augmented by remote messages or change their meaning without
updating the RFC:

```text
MAX_INFLIGHT_SNAPSHOTS       = 2
MAX_SNAPSHOT_CHUNKS           = 256
MAX_SNAPSHOT_BYTES            = 4 MiB
MAX_CHUNK_LSAS                = 512
MAX_SNAPSHOT_LSAS             = 65536
MAX_SNAPSHOT_NEIGHBORS        = 262144
MAX_NEIGHBORS_PER_LSA          = 1024
SNAPSHOT_REASSEMBLY_TIMEOUT   = 10 s
SNAPSHOT_ACK_TIMEOUT          = 10 s
MAX_PENDING_DELTAS_PER_LINK   = 4096
MAX_TOPOLOGY_SYNC_STREAMS_PER_LINK = 32
MAX_RECOVERY_STREAMS_PER_LINK      = 1
MIN_SNAPSHOT_REQUEST_INTERVAL  = 10 s
MAX_SNAPSHOT_RECOVERY_ATTEMPTS_PER_EPOCH = 3
```

`MAX_SNAPSHOT_BYTES` limits the estimated memory occupied by both cached encoded bytes and decoded
LSAs; implementations must check before caching and decoding, and cannot allocate unbounded first
and then judge. `MAX_SNAPSHOT_NEIGHBORS` is calculated cumulatively by decoded neighbor entries and
checked before signature verification, topology apply, and path recalculation.
`MAX_NEIGHBORS_PER_LSA` is the protocol validation upper limit for LSAs: any locally generated and
received LSAs exceeding this value must be rejected. This value ensures that, together with the
TopologySync fixed field, a complete LSA can still fit into a single `u16::MAX` control body;
therefore implementations MUST NOT truncate or break an LSA into undefined fragments.
`MAX_TOPOLOGY_SYNC_STREAMS_PER_LINK` only limits ordinary TopologySync streams; ACK and Request
share a reserved `MAX_RECOVERY_STREAMS_PER_LINK` recovery slot, which must not be occupied by
ordinary TopologySync. This recovery slot also counts against RFC-0017's total S1 writer cap, which
must be at least `MAX_TOPOLOGY_SYNC_STREAMS_PER_LINK + MAX_RECOVERY_STREAMS_PER_LINK`. When ordinary
TopologySync exceeds the upper limit, it is not allowed to continue to create new streams, and
should wait for the completion of the existing stream; if the receiver accepts the stream, it must
first be restricted to read and release it, and the peer cannot permanently occupy the flow-control
resource.

The receiver must set the local state to `SnapshotRequired` after rejection or reassembly timeout,
and request the sender to send the latest complete Snapshot of the current epoch. Each receiving
direction can send a Request at least `MIN_SNAPSHOT_REQUEST_INTERVAL` apart; failures within this
interval must be combined into one state to be recovered, and Request cannot be sent repeatedly.
The sender must retain the Snapshot content or the equivalent rebuildable state that has not
received the ACK until the corresponding ACK is received, the Link epoch ends, or a new
SnapshotRequired recovery process is entered. The sender must start `SNAPSHOT_ACK_TIMEOUT` after all
chunk streams of the same Snapshot are successfully written and EOF; ACKs received before this are
still processed normally as `sync_id`. The timer must not be reset due to repeated requests, late
ACKs, or irrelevant control messages, and must be canceled at the end of the Link epoch. Request and
ACK timeouts share the `MAX_SNAPSHOT_RECOVERY_ATTEMPTS_PER_EPOCH` recovery budget per send direction
and per epoch: the budget is consumed each time a new complete Snapshot is queued; after receiving
the Request, if no Snapshot is sending or waiting for ACK, the old Delta is paused, the
unrecoverable Delta queue is cleared, and a new complete Snapshot is queued; otherwise, the Request
is merged. When the ACK times out, the Link must be set to `SnapshotRequired`, the waiting status of
the current active Snapshot must be discarded, and a new complete Snapshot must be queued according
to the same rules; the same batch of chunks must not be replayed. If the budget required for any of
the above steps has been exhausted, the Link must be closed immediately.

This budget only limits Snapshot work within a single Link epoch and must not disable or exhaust the
adjacency's reconnect responsibilities. When a Link is closed due to budget exhaustion, the
distinguishable `topology_sync_recovery_budget_exhausted` reason must be recorded; the party
responsible for reconnection must regard it as an ordinary recoverable Link closure and continue to
initiate new authentication connections according to the existing bounded backoff. The new epoch
uses an independent budget and must still re-execute the bidirectional initial Snapshot. The
synchronization success status of the old epoch cannot be reused. The sender can only accept
`TopologySyncAck` that exactly matches the current active Snapshot `sync_id` and is waiting for the
ACK; late ACKs that are unknown, confirmed, or replaced by a new recovery Snapshot must be silently
ignored and counted, and the synchronization status cannot be switched or the current Snapshot is
released.

Snapshot recovery is directional. When the receiver sends a `TopologySyncRequest`, it marks only
its receiving direction as `SnapshotRequired`. When it receives a request from its peer, it marks
only its sending direction as `SnapshotRequired`. Recovery in one direction must not clear
Snapshot or ACK state that has already completed in the other direction.

If the receiver has atomically applied a Snapshot and later returns to `AwaitingInitial` because of
a missing Delta, ACK, or recovery event, it may accept a repeated Snapshot with the same `sync_id`
only if no newer Snapshot generation has been observed. After applying that repeated Snapshot and
sending its ACK, the receiver may restore the receiving direction to `Synchronized`. If it has
observed a newer generation, it may resend the ACK for the old Snapshot but must not restore the
old synchronized state or interrupt a newer transfer with duplicate fragments. Snapshots below
the receiving direction's generation watermark are ignored before replacing any active assembly.
The same generation may finish an interrupted assembly; a newer generation may replace it and
advance the watermark. The watermark is discarded when the Link epoch ends, so a new epoch does
not use the previous connection's generation as its freshness baseline.

If a `TopologySyncRequest` cannot be delivered because local admission rejects it, the control
stream write fails, or the connection has closed, the Link epoch records the distinct reason
`topology_sync_recovery_request_delivery_failed` and closes. It must not remain indefinitely in
`SnapshotRequired` after only logging the failure. The reconnection owner performs normal Link
shutdown and establishes a new epoch, which repeats the bidirectional initial Snapshot.

When a transfer with a new `sync_id` replaces an unfinished assembly, the old assembly is released
immediately. It must not continue to consume reassembly resources or trigger another recovery
after the new Snapshot succeeds. Late fragments for an assembly replaced by a newer transfer or
abandoned after a reassembly timeout are silently ignored within the bounded superseded-ID window
(the current implementation retains the latest 16 IDs). Exhausting the recovery budget closes the
Link; retries are then handled by the existing bounded connection backoff.

The sender must not consider a Snapshot synchronized at the application layer until it has been
successfully submitted and acknowledged. While waiting for the ACK, it may continue processing S0
according to RFC-0017, but must not send stale Deltas. It must not send duplicate
`TopologySyncRequest` messages or replay the same failed batch of Deltas.
The current Snapshot must be discarded in the following situations:

- Duplicate `chunk_index`;
- The `chunk_count` or mode of the same `sync_id` is inconsistent;
- Decoding of any LSA in the chunk failed;
- The number of chunks received exceeds the declared value;
- Link epoch ends;
- Reassembly timeout;
- Resource limit exceeded.

Dropping should not remove old topologies that have been committed, nor should the entire Link be
closed, unless this behavior falls within an existing control stream protocol error handling policy.
The current Link enters `SnapshotRequired`, and the old Delta of the Link is paused before the new
Snapshot is submitted successfully and the ACK interaction is completed. The complete Snapshot must
be resent in the next Link epoch.

### Delta semantics

After the topology database accepts a new LSA, the node must update the Reliable Delta queue for all
neighboring links that need to receive the status. Delta is a reliable notification, not a
confirmation, nor an authoritative database operation.

The pending delta of each link must use a bounded table merged by origin: the same origin only
retains the complete current LSA corresponding to the highest sequence, and the table capacity must
not exceed `MAX_PENDING_DELTAS_PER_LINK`. Overwriting the old Delta is only allowed when the LSA
represents the complete current state of the origin; if incremental operations are introduced in
the future, a separate RFC must be opened to define operational dependencies.

When the relay forwards topology changes, it must update the delta queue of the outbound link after
processing the inbound LSA, and finally send the Reliable Delta through the control stream. You
cannot just call `send_physical(Topology)`. When an outbound delta is enqueued, stream opened, or
writes fail, the Link must be made to enter `SnapshotRequired`, the old delta is paused, and a new
complete Snapshot is queued; it cannot wait for the next topology change to trigger recovery.

The recipient must:

1. Verify the signature and structure of each LSA;
2. Perform existing replay/freshness judgment based on origin and sequence;
3. Ignore duplicate or older LSAs;
4. For the accepted new LSA, the topology is updated according to the existing rules and triggers
   path recalculation;
5. Do not delete existing state just because Delta is missing some origin.

Reliable Delta does not rely on Physical sequence or Physical replay window. QUIC stream's reliable
delivery, Link epoch and LSA origin/sequence deduplication jointly ensure synchronization;
TopologySync does not update Physical data plane liveness. Implementations should maintain
`last_authenticated_physical_rx` and `last_control_stream_rx` separately; control stream activity
cannot bypass Physical idle detection alone.

## Send and receive state machines

### sender

Each Link epoch must maintain an independent topology synchronization state:

```text
Disconnected
    ↓
SnapshotQueued
    ↓
SnapshotSending
    ↓
Synchronized
└─Failed to send/receive→ SnapshotRequired
└─ACK of the current active Snapshot→ Synchronized
```

- After the link is established, both parties immediately queue Snapshots in their own sending
  direction; each sending direction independently maintains `sync_id`, Snapshot state and Delta
  queues.
- New LSAs generated when the Snapshot has not yet been sent must be merged into subsequent
  Reliable Delta; fixed Snapshot chunks must not be modified.
- When Reliable stream is under back pressure, Delta is merged by origin and the queue is bounded.
  When the queue is full or any sending step fails, Link enters `SnapshotRequired`, clears the old
  Delta, repins and sends the complete Snapshot.
- A healthy Link must not be closed when the queue is full (fanout fails to join the queue): the
  sender clears the old Delta of the Link, marks the two local directions as unsynchronized, and
  sends a recovery Request to the peer; after the peer replies with its current Snapshot, if the
  receiving path finds that the local sending direction is still not synchronized, it will refix
  and send the local Snapshot to complete recovery in both directions (the Link is closed only
  when the Recovery Request cannot be delivered and handed over to the party responsible for
  reconnection to rebuild the epoch).
- `SnapshotRequired` state prohibits continuing to send old Delta; only switch to `Synchronized`
  after receiving `TopologySyncAck` of the current active Snapshot, and then send the latest Delta
  accumulated during the period. ACKs from unknown, duplicate, or replaced Snapshots shall not
  change this state.
- When the Link is closed, the pending Delta and unpublished Snapshots of the Link epoch are
  discarded; the new epoch must resend the complete Snapshot, so topology changes cannot be lost
  by discarding the pending Delta of the old epoch.

### Receiver

Each Link epoch must maintain:

- The reorganization table of the Snapshot is currently unfinished;
- A limited window of current and recently completed Snapshot IDs;
- State of the most recently successfully verified control message on this Link (if required by
  the implementation);
- LSA freshness judgment shared with the global Topology database.

Completed Snapshot IDs must not be saved using an unbounded collection; each epoch retains at least
the current Snapshot and a limited window of the most recently completed. The completed ID is
silently discarded when it arrives again, and all reorganization and deduplication statuses are
released when the Link epoch ends.

Reception order should not be assumed:

- Snapshot chunks and delta may arrive staggered;
- The completion order of different QUIC uni streams does not represent the sending order;
- Tasks from the old Link epoch must not be written to the state of the new Link epoch.

All messages are ultimately judged by LSA origin/sequence, so reordering will not cause old LSAs to
overwrite new LSAs. Delta can arrive before the Snapshot is completed and can be applied normally;
after the Snapshot is completed, LSAs of the same or older sequence are ignored according to replay
rules. Snapshot completion triggers path recalculation at most once.

The reception threshold of Delta only depends on the local RX state machine (the current Snapshot
has been submitted): the peer only starts flushing Delta after the local ACKs its peer Snapshot, so
the RX must be ready when the legal Delta arrives; "the local outbound Snapshot has been ACKed" must
no longer be used as a Delta reception condition - outbound ACK and peer Delta go through a
different uni stream, and the completion order is not guaranteed. Misuse of this condition will
falsely trigger recovery when the ACK is late and consume the peer's recovery budget.

## Link establishment, reconnection and failure recovery

### New Link

After the identity Hello/HelloAck is successful and the Link is installed, both parties must send a
Snapshot each. The receiver cannot regard the Link as unavailable because the Snapshot has not been
received; however, the missing path must not be regarded as confirmed to be reachable before the
topology synchronization is completed. The Link of the current epoch will only enter `TopologyReady`
after the local end has submitted the peer's initial Snapshot and the local end's initial Snapshot
has received a matching ACK. Prior to this, the Link can complete the identity handshake and S0
control operations, but the topology routing and Circuit controller must not treat it as a restored
topology path.

### Reliable stream interrupt

If the read of the stream where the Snapshot or Delta is located fails:

- Completely committed LSAs may not be rolled back;
- Incompletely submitted Snapshots must be discarded;
- When the current Link still exists, you must enter `SnapshotRequired` and requeue a new
  Snapshot;
- If the receiver detects decoding, resource or verification failure, `TopologySyncRequest` must
  be sent;
- The same batch of expired Deltas may not be retried indefinitely;
- If the Link is closed, wait for the new Link epoch to resynchronize.

### Link reconnect

The new Link epoch must resend the full Snapshot, even if the topology databases at both ends of the
new Link look the same. Snapshot/Delta of the old epoch cannot continue to be sent to the new Link
through asynchronous tasks.

It is legal for the same LSA to be received again after reconnection; existing sequence/replay logic
must recognize this as a duplicate and not an error.

### Continuous reconnection and eventual recovery

Each Link configured as a long-lived adjacency must designate at least one reconnection responsible
party; deployments typically assume this responsibility with an active `connect_to` configuration at
one end. The daemon of the responsible party must not permanently stop trying due to
pre-authentication failure, Link shutdown, `SnapshotRequired`, exhaustion of the ACK recovery
budget, or the number of consecutive failures; backoff can only reduce the frequency of attempts and
cannot mark the adjacency as permanently disabled. A deployment with only passive accept without any
responsible party does not meet the eventual recovery guarantees of this RFC.

The liveness guarantee of this RFC is conditional: if the daemon continues to run, at least one
party assumes reconnection responsibility, the identity and configuration remain compatible, and
after the fault is eliminated, there is a continuously available transmission window sufficient to
complete dialing, authentication, two-way Snapshot/ACK and local scheduling, then the responsible
party will eventually establish a new Link epoch, and both parties will eventually enter
`TopologyReady`. Afterwards, a path recalculation and reconciliation of the existing Circuit
controller must be triggered; the failed Circuit can be re-established according to the existing
security status machine, but authorization must not be bypassed or the old end-to-end session
directly restored on the path that has not restored `TopologyReady`. This guarantee does not claim a
fixed upper limit for wall clock recovery, nor does it apply to situations where the network is
continuously disconnected, the peer is down, permanent authentication failure, or there is never
enough available window.

> This semantics has been replaced by RFC-0027: the daemon no longer supports hot reloading, and
  path configuration changes must be completely restarted. This record is only kept to illustrate
  the reconcile race conditions that need to be handled before 2026-08-09.

Physical keepalives are proofs of adjacency liveness that are independent of the control stream. The
maintenance task must first check and send the expired authentication Physical keepalive, and cannot
wait for Ping, TopologySync or other writer/flow-controls that control the stream; otherwise, the
stream backpressure during reconnection will incorrectly determine the healthy but idle Physical
carrier as an idle timeout.

### LSA reliable lease renewal

Each origin must check its local LSA with a period not greater than `keepalive_secs`; if the LSA
will expire before the next check, or its adjacency attributes change, a new complete LSA must be
generated. The sequence of the renewed LSA must be strictly greater than the published sequence of
the same origin, and `expires_at` must be later than the generation time and sent to each
`TopologyReady` adjacency according to Delta semantics; Links that are not yet ready or in
`SnapshotRequired` must obtain the latest LSA in their next full Snapshot. Implementation and
configuration verification must ensure `keepalive_secs < LSA_TTL` so that there is at least one
reliable propagation opportunity; the specific values   of TTL and lease renewal period continue to
use existing configurations/constants, and no new user configuration items are added in this RFC.

Lease renewal only controls LSA Delta on the stream and may not reintroduce `FORM_TOPOLOGY` or other
Physical Topology refresh. If the lease renewal fails, the Delta failure recovery process of this
RFC must be followed and cannot be skipped silently; therefore, the static topology on the healthy
link will not disappear due to the natural expiration of the TTL.

### Sender crashes or restarts

After restarting, a new LSA is allowed to be constructed from the origin sequence starting point,
but the existing topology sequence life cycle rules must be followed. If sequence persistence or
restart semantics need to be changed, another RFC must be issued; this RFC does not define sequence
persistence across restarts.

## Backpressure, priority and resource control

Topology synchronization must not be a source of unbounded memory or control plane blocking:

- Snapshot must have limited snapshot size, chunk count, cache bytes, and reassembly timeout;
- Delta queues must have limited capacity;
- The pending old delta of the same origin can be replaced by the delta of a higher sequence;
- Snapshot and Delta must not block OPEN/ACK, RENEW, CLOSE and Ping/Pong;
- Only `TopologyReady` Link can be used by topology routing and Circuit controller as a restored
  path; when returning from `TopologyReady` to `SnapshotRequired` or Link is closed, path
  recalculation and reconciliation must be triggered;
- The same Link shall not send multiple complete Snapshots at the same time;
- The failure to send Reliable Sync must not trigger data plane retransmission or affect Circuit
  DATA, but it must cause the Link to enter `SnapshotRequired` or be restored by a new Link epoch;
- Reliable Sync must follow the connection-level control admission of RFC-0017; TopologySync
  belongs to S1, and OPEN/ACK, CLOSE/RENEW, and PING/PONG belong to S0. TopologySync must not
  bypass the per-Link control stream concurrency limit through unlimited concurrency `open_uni()`;

If the topology scale cannot complete the Snapshot within the implementation limit, the
synchronization party must record the reason for the limitation and keep the existing topology. It
is not allowed to send partial snapshots and then treat them as full snapshots. A single LSA that
meets `MAX_NEIGHBORS_PER_LSA` must be propagated through Reliable Delta or Snapshot sharding; LSAs
exceeding this limit are rejected when generated or received with explicit operation and maintenance
visible errors, and cannot be truncated or split into undefined fragments that cannot be
independently verified.

## security impact

### identity and integrity

Reliable Sync runs on Links that have completed QUIC TLS and Tinect signed Hello, but TLS
authentication does not replace LSA origin signature. The recipient must still verify:

- `public_key` can correctly verify LSA signature;
- LSA origin corresponds to the signature public key;
- Fields such as neighbor, cost, datagram_mtu meet existing range and structure checks;
- `expires_at`, origin sequence and replay rules are legal.

### replay and shuffle

QUIC stream itself does not allow repeated delivery of the same stream bytes, but reconnection and
repeated transmission will still cause the same LSA to arrive multiple times. Therefore, the
origin/sequence deduplication of LSA must be retained and cannot be replaced by "stream reliable".

The `sync_id` of the Snapshot chunk is used for both reorganization and Snapshot generation sorting
within the current Link epoch, but is not a proof of freshness of the LSA content; LSA sequence
verification cannot be bypassed based on a larger `sync_id`.

### DoS

The remote end can consume memory, CPU, and QUIC stream resources through large Snapshot chunks,
extremely large `chunk_count`, or high-frequency delta. Therefore, the upper limit, timeout, and
merging rules defined in this article must be used, and the number of concurrent control streams for
a single Link must be limited. Messages with unknown control kind, illegal mode, illegal chunk
metadata, or exceeding the body limit must be rejected.

TopologySync must not change local system routing, TUN, NAT, or firewall; it only updates the
in-memory topology and triggers recalculation of existing paths.

## Compatibility and migration

This RFC adds control messages kind 25, 26, and 27, and changes the transmission responsibilities of
Topology:

- `FORM_TOPOLOGY (0x01)` is no longer used for Topology; new nodes must not send or receive
  Topology via Physical DATAGRAM;
- kind 26 and kind 27 are used for Snapshot ACK and recovery requests respectively;
- Hello/HelloAck must negotiate the `reliable_topology_stream` capability. RFC-0016 is allowed to
  be enabled on the Link only if both parties declare the capability; the authentication scope of
  the capability is the same as the existing signed Hello/HelloAck;
- This field changes the length of Hello/HelloAck, which is an intentional incompatible protocol
  change; nodes that do not support this capability or the old format cannot establish links with
  RFC-0016 nodes. The implementation must reject such Link during the link building stage and
  cannot wait until receiving kind 25 before entering the semi-compatible state;
- This RFC does not define downgrades or rolling upgrades of old and new topology transport
  methods. The deployment must fully upgrade all interconnected nodes before enabling them. When
  capability negotiation fails, the implicit fallback compatible with old nodes must not be
  enabled;
- New implementations MUST NOT treat received unknown kind as a successful TopologySync;
- Before all nodes are upgraded, you must not rely on the new guarantee of "having a complete
  topology immediately after building the link".

When capability negotiation fails, both parties MUST log an explicit compatibility error and MUST
NOT install an available topology control plane.

## Realize boundaries

Implementations should maintain the following layering:

- `topology`: Only responsible for LSA encoding and decoding, signature verification, sequence/TTL
  and database apply; does not perform stream or socket I/O.
- `control`: Add TopologySync control message encoding, decoding and bounds checking.
- `carrier`: Responsible for reliable control of stream sending/receiving, but does not determine
  topology database semantics.
- `dataplane`: Responsible for the topology processing entry of Reliable Snapshot/Delta, as well
  as Delta merging, Snapshot reorganization and Link epoch life cycle.
- `physical`: No longer responsible for Topology payload; Physical form `0x01` must be left unused
  or rejected as retained form, and cannot be reused into other incompatible data formats.

Implementations MUST NOT bypass existing LSA signature verification, nor allow unvalidated LSAs to
enter the forwarding, routing, or LSA re-propagation queues.

## Testing and Acceptance Criteria

### Codec

1. TopologySync's Snapshot, Delta, illegal mode and boundary length round-trip.
2. Reject if `chunk_index`, `chunk_count`, `sync_id` are inconsistent.
3. The body exceeds `u16`, chunk_count is zero, Delta multiple chunks, and duplicate chunks are
   all rejected; TopologySync whose body is exactly `u16::MAX` can be completely read by the
   dedicated receive path.
4. The behavior of an empty Snapshot is unambiguous and does not delete the database status.
5. The codec and unknown reason behaviors of `TopologySyncAck` and `TopologySyncRequest` are
   clear.

### Reorganization and sequencing

1. Snapshot chunks can be fully committed after arriving out of order.
2. Missing chunks are not treated as complete Snapshots.
3. Duplicate LSAs, old LSAs, and out-of-order delta all get the same final database status.
4. Old incomplete Snapshots are being cleaned up correctly or timing out when a new Snapshot
   arrives.
5. After the Link epoch changes, the chunks of the old epoch must not be written into the
   reorganization state of the new Link.
6. Bidirectional Link epoch can send Snapshot at the same time, and the `sync_id` and state in
   both directions do not affect each other; a recovery request in one direction cannot clear the
   state in the other direction, and a duplicate packet for a completed Snapshot restores the
   RX state after its ACK is sent successfully.
7. Snapshots that have not received an ACK can be reconstructed or resent; the latest complete
   Snapshot is sent after receiving the Request.

### Failure and backpressure

1. After the Snapshot stream is interrupted, the complete old state is retained, and the
   incomplete Snapshot is discarded.
2. Link automatically sends a complete Snapshot after reconnection.
3. Reliable Snapshot can be fragmented when a large topology exceeds the limit of a single
   control message.
4. When a large number of deltas are merged, each origin ends up retaining only the highest
   unsent sequence, and the queue remains bounded.
5. After Delta enqueue, stream open or write failure, Link goes to `SnapshotRequired` and
   completes recovery.
6. Topology sync backpressure must not block OPEN/ACK, RENEW, CLOSE, Ping/Pong or Circuit DATA.
7. Failure in admission or writing of the Recovery Request will close the current Link epoch, and
   the party responsible for reconnection will re-establish the link and perform a bidirectional
   Snapshot without waiting for subsequent Delta or control messages.
8. When active Snapshot receives a Request while waiting for ACK, the Delta generated by Snapshot
   will not be discarded; these Deltas will still be sent after ACK.
9. When Snapshots with different `sync_id` are interleaved or the old Snapshot times out, the old
   assembly will be cleaned up immediately and the superseded ID will be recorded; old deadline
   or late sharding will not trigger recovery again after the new Snapshot succeeds, nor will the
   new assembly be cleared. Snapshots below the RX generation watermark will not be reassembled
   or applied even after the limited completed/superseded ID window has passed.
10. When any LSA in the Snapshot fails verification, the entire Snapshot must not produce
    database changes.

### Safety

1. LSA field, signature, public key and origin tampering in any Snapshot/Delta is rejected.
2. Forging a larger Snapshot `sync_id` or a larger LSA sequence cannot bypass freshness
   verification.
3. Oversized chunk_count, oversized number of shards, and duplicate streams must not result in
   unbounded allocations.
4. Unverified LSAs must not trigger path recalculation, topology re-propagation, or circuit
   establishment.
5. TopologySync must not incorrectly refresh Physical data plane liveness upon arrival.
6. ACK is sent after Snapshot is submitted; Request is sent after decoding, resource or
   verification failure; ACK timing starts only after all chunks are successfully written.
   Timeout will consume the determined recovery budget and enter bounded recovery or Link
   reconnection backoff.
7. Expired LSAs in the Snapshot are ignored, but other valid LSAs can still be submitted.
8. When the number of neighbor entries, Snapshot bytes, LSAs, and TopologySync streams exceeds
   the upper limit, unbounded allocation or path recalculation will not be triggered.
9. Ordinary TopologySync cannot occupy the recovery slot; ACK/Request can still complete bounded
   sending when the ordinary stream reaches the upper limit.
10. Local or remote LSAs exceeding `MAX_NEIGHBORS_PER_LSA` are rejected and do not trigger
    topology update or re-propagation.
11. Repeated Requests, ACK timeouts, and malicious non-ACKs are all limited by the recovery
    interval and epoch recovery budget; after the budget is exhausted, Link uses the reconnect backoff to
    close, and unlimited Snapshots are not generated.
12. Only ACKs from the currently active Snapshot can switch to `Synchronized`; ACKs from late,
    duplicate, unknown, or superseded Snapshots are ignored and the current Snapshot is not
    released or the old delta is sent.
13. After the static adjacency runs for more than multiple LSA TTLs, the origin still generates
    a higher sequence reliable lease renewal Delta according to `keepalive_secs`; the receiver
    topology will not disappear due to the expiration of the original LSA, and no Physical
    Topology will be sent.
14. Each long-lived adjacency has an observable reconnection responsible party; its link
    shutdown after the recovery budget is exhausted does not stop subsequent dialing. After the
    network is restored and stable, the new epoch completes the bidirectional Snapshot/ACK,
    enters `TopologyReady`, and then path recalculation and Circuit reconcile occur once.

### Network integration acceptance

Verify in Linux CI:

- Synchronize the topology immediately after the two-node link is established;
- Three-node topology changes must pass Reliable Delta convergence;
- Relays must forward Delta via the outbound control stream;
- The unfinished Snapshot of the old Link after reconnection will not affect the new Link;
- Fragmentation, reassembly, and expiration cleanup of large numbers of LSAs;
- Artificially block the network until the Snapshot recovery budget is exhausted and the Link is
  closed, and then restore the network; verify that the party responsible for reconnection
  continues to redial, the new epoch bidirectionally enters `TopologyReady`, the static LSA has
  been reliably renewed, and the path and circuit are restored without bypassing authorization;
- After the test, confirm that Link, process, namespace, TUN, routing and firewall resources have
  been cleared.

## Open Questions

- The allocation and specific semantics of subsequent capability bits need to be defined in
  separate RFCs; bits `0` and `reliable_topology_stream` are fixed by this RFC.

## Implementation Notes

Implemented. `ControlMessage` kind 25, 26, 27 carry `TopologySync`, ACK and Request; Hello/HelloAck
negotiates `reliable_topology_stream` with capability bit 0, and unsupported peers are rejected.
`FORM_TOPOLOGY (0x01)` has been reserved and refused to be received. Physical only retains encrypted
empty keepalives to maintain the underlying liveness.

Each Link epoch first sends, reassembles and atomically submits Snapshot in both directions, and
then enters `TopologyReady` after receiving a matching ACK; an unready Link does not participate in
topology routing or Circuit first hop selection. Snapshot ACK, Request, reassembly
bytes/LSA/neighbor/concurrency number and timeout are all capped. Timeout or Request will resend the
current Snapshot; exhaustion of the recovery budget will close the Link, and the dial supervisor of
`connect_to` will continue to reconnect according to bounded backoff. Any Snapshot decoding,
resource or verification failure will immediately exit `TopologyReady`; Requests are sent in each
direction at most every 10 seconds, and duplicate Requests are merged when there are active
Snapshots without resetting the ACK timeout or consuming additional budget. The completed Snapshot
ID retains a limited window to discard duplicate transmissions; the receiving direction additionally
retains the largest Snapshot generation watermark observed within the current Link epoch. Snapshots
lower than the watermark are directly discarded in the receiving phase and will not be re-applied
because the ID window elimination has been completed; repeated Snapshots of the same generation will
only restore the `Synchronized` state of the receiving state machine when the ACK is successful
and the recovery conditions are still met, and will not change the other direction; Configuration
verification requires that `keepalive_secs` is less than the LSA TTL, and a single local LSA will
not exceed the neighbor upper limit. When the recovery request cannot be delivered, the current Link
will be closed with `topology_sync_recovery_request_delivery_failed`, and the party responsible for
reconnection will re-establish the epoch to avoid unsynchronized state triggering recovery by
relying on subsequent accidental messages. When a new `sync_id` takes over the RX state machine or
the old Snapshot reorganization times out, it will immediately clean up the old unfinished assembly
and suppress its late fragmentation in the bounded superseded-ID window to avoid the old
reorganization deadline from downgrading the Link again after the new Snapshot has been submitted.
Each Link maintains a maximum of 4096 pending Deltas merged by origin; only the latest values   are
retained during synchronization and when re-fixing the Snapshot, and are emptied by the control
processor of the epoch after entering `TopologyReady`. Stable adjacency generates a higher sequence
of reliable delta according to `keepalive_secs` to renew the LSA.

Network fault injection covers three nodes. After establishing a circuit, the egress, relay and
source node processes are terminated in sequence, and it is verified that the chain is
re-established, circuit recovery is completed and network resources are cleaned and isolated within
the recovery period.
