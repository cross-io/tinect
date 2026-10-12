# RFC-0024: Sync failure observability and data plane rejection reasons

- Number: RFC-0024
- Title: sync-failure-observability-and-rejection-reasons
- Status: Implemented
- Created: 2026-08-05
- Last updated: 2026-08-17

## Background and Problem

RFC-0016 puts topology Snapshot/ACK on a reliable QUIC stream and specifies a fixed ACK timeout and
bounded recovery budget. This guarantees that the topology will not use expired views indefinitely,
but the current implementation still has two engineering issues:

1. Sending error ignored when sending `TopologySyncAck` after receiving full Snapshot. ACK
   admission is rejected, stream opening fails, or writing fails, which ultimately only manifests
   itself as "ACK timeout" on the sending end. Control plane backpressure, peer closure, and
   underlying path packet loss cannot be distinguished.
2. When the sending gate is not opened, the data plane shares `packet:exceeds_path_mtu` with the
   real inner packet exceeding the physical budget. This will falsely report that the
   circuit/lease is not ready as an MTU error, and mislead the operation and maintenance to deal
   with the real topology problem by increasing the MTU or waiting time.

The transoceanic path from Shanghai to Tokyo allows for short-term packet loss and sudden delays.
Therefore, the system must provide sufficient evidence to determine whether a failure is local
admission, control stream, topology verification, or underlay packet loss without relaxing the
security boundary or infinite retries. Topology failures cannot be swallowed silently, otherwise the
healthy link will be forcibly closed by the recovery budget after 30 seconds, and only a contextless
timeout will be seen on site.

## Target

- Provides structured logs with `sync_id` for Snapshot send, receive, ACK send, and recovery
  retries.
- ACK is sent using bounded, cancelable short retries; the 10-second ACK deadline of RFC-0016 and
  the upper limit of recovery times per Link epoch are not changed.
- Explicitly log ACK delivery failures as control plane errors, and leave connection close errors
  with their original cause.
- Split data plane rejection into lease not ready, real inner packet exceeds the current physical
  budget and binding unavailable, ensuring one-to-one correspondence between counters and log
  semantics.
- Keep all wire frame, signature, key, ACL and relay opaque boundaries intact.
- Allow unit tests to verify error classification and retry policies without creating TUNs or
  modifying routes.

## Non-goals

- Do not increase the Snapshot ACK deadline to cover up packet loss or achieve blocking.
- It does not turn QUIC DATAGRAM into a reliable data plane, nor does it add fragmentation or
  retransmission to the inner packet.
- Does not change RFC-0016's Snapshot atomic commit, TopologyReady threshold, recovery budget, or
  LSA lifecycle.
- Does not change path capacity calculation, PMTU detection, and active lease semantics of
  RFC-0018/RFC-0022.
- Do not incorporate `fwmark`, policy routing, or underlay selection into the tinect protocol;
  these are still the responsibility of the deployment configuration.

## the term

- **ACK send attempt**: A bounded attempt to call `send_control(TopologySyncAck)` on the specified
  `sync_id`.
- **control plane error**: ACK/Request/Snapshot control stream admission, QUIC stream, protocol,
  or peer shutdown error; not equivalent to data plane packet loss.
- **Lease not ready**: The route has selected the destination, but the sending gate of the active
  circuit has not yet been opened, or the old lease has been revoked.
- **Real MTU Rejection**: The sending gate is open, but the packet after encryption and Physical
  envelope does exceed the current `send_budget`.

## design

### 1. ACK sent

After the receiver completes all decoding, verification, and atomic submission of the Snapshot, it
still marks that the local end has received the Snapshot before sending an ACK. ACK sending must
satisfy:

```text
TOPOLOGY_ACK_SEND_TIMEOUT = 1 s
MAX_TOPOLOGY_ACK_SEND_ATTEMPTS = 3
```

Each attempt goes through the existing RFC-0017 admission and recovery writer; at `open_uni` or if
the write period exceeds 1 second, the attempt is canceled and its permit is released. Use short
backoffs of 50 ms, 100 ms between attempts. If the connection has been closed, stop trying
immediately; for other errors, try again only within the budget. When all three attempts fail:

- Record warnings with peer, Link instance, `sync_id`, attempt and error types;
- Mark local topology sync as incomplete;
- No forged ACKs, no increased recovery budget;
- Let the peer continue to perform Snapshot recovery according to the original ACK deadline of
  RFC-0016.

Both successful and failed ACK transmissions must contain `sync_id`, so that the logs at both ends
can be associated through the same ID.

### 2. Snapshot/Recovery log

The following events must include peer and Link instance; when involving Snapshot, `sync_id` must
also be included:

- initial/recovery Snapshot send started,sent,send failed;
- Snapshot received,committed,rejected;
- ACK send attempt,ACK sent,ACK send exhausted;
- ACK received,stale ACK ignored;
- recovery budget exhausted.

Error types distinguish at least `admission_rejected`, `stream_open`, `stream_write`,
`connection_closed`, `timeout`, and `protocol`. Logs must not record keys, inner payloads, or full
LSA contents.

The timing and shutdown semantics of the existing `topology snapshot recovery budget exhausted`
remain unchanged; this RFC only supplements the root cause evidence to avoid changing the
convergence model by blindly extending the waiting time.

### 3. Data plane refuses to classify

Source node send checks are performed in the following order:

```text
if binding does not exist or is unhealthy:
    route:binding_unavailable
else if send_gate is not open:
    lease:not_ready
else if inner_packet_fits_current_budget is false:
    packet:exceeds_path_mtu
else:
Encrypt and send
```

`lease:not_ready` must not be added to `packet:exceeds_path_mtu`, and the "packet exceeds current
send budget" warning must not be output. The real MTU rejection must record both the packet byte
count and the physical budget; the lease is not ready and only needs to be recorded at the debug
level to avoid screen flushing during the short reconstruction period caused by cross-ocean packet
loss.

After the packet has entered the encryption queue, the sending worker will still recheck the gate
and current budget before encryption and before each carrier send attempt. The classification rules
are as follows:

- `lease:stale_epoch` is recorded when the gate is closed (lease epoch has expired);
- `packet:exceeds_path_mtu` is logged when the gate is open but the packet exceeds the current
  budget.

`lease:stale_or_over_budget` is no longer a valid reason for sending workers, and dashboards and
alerts must not rely on the old name; the source TUN entry continues to use the `lease:not_ready`
and `packet:exceeds_path_mtu` categories defined in this section.

### 4. Compatibility and performance

- Without modifying the on-the-wire control message, Physical frame, or OPEN wire format, older
  versions will not fail to decode due to new fields.
- ACK retries add up to 3 seconds to the local control task time and are canceled by connection
  close; there is only one attempt for the normal path.
- The log only records limited scalar fields; each LSA or packet is not saved to avoid unbounded
  memory and log growth caused by long-term operation across oceans.
- Data plane rejection is still O(1) atomic reading and counting, and no locks or extra packet
  clones are introduced.

## security impact

ACK is still only sent after the full Snapshot is atomically committed; retries do not skip
signature, sequence, expiration, and TopologyReady checks. Does not mark the link as ready on
failure, nor relax the lease gate or physical budget. The log fields come from the local state of
the authenticated Link and do not expose the private key, token or inner IP content.

## Testing and Acceptance Criteria

- The ACK successful path only sends ACK once and records the corresponding `sync_id`.
- ACK admission/stream timeout/connection close can end after a bounded attempt without holding a
  writer permit and without increasing the recovery budget.
- Three failed ACKs will not mark the uncommitted Snapshot as ready.
- When `send_gate=false`, packet 84, budget 1460, the count is `lease:not_ready` and
  `packet:exceeds_path_mtu` is not included.
- `packet:exceeds_path_mtu` is only counted when the send gate is open and the packet exceeds the
  budget.
- Existing RFC-0016/0018/0022, real network integration and cleanup tests continue to pass.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  and related Nix packaging checks passed.

## Implementation Notes

The implementation includes bounded ACK retries, control plane logs with Link instance/`sync_id`,
and source lease/MTU rejection classification. Network integration acceptance covers multi-hop
paths, link recovery, and control plane convergence; telemetry is used to distinguish rejection
reasons such as topology recovery budget exhaustion, sending capacity exceeding, and lease not yet
ready.
