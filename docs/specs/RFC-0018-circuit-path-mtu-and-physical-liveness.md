# RFC-0018: circuit path MTU and physical liveness

> RFC-0046 removes the path MTU field in OPEN; this RFC still defines LSA capacity, active
  circuit's local send budget, and carrier-local precision precheck.

- Number: RFC-0018
- Status: Implemented
- Title: circuit-path-mtu-and-physical-liveness
- Created: 2026-07-31
- Last updated: 2026-08-27
- Change record: 2026-08-03 Added the relay forwarding evolution boundary of RFC-0022; RFC-0022
  Implemented, the current relay behavior is subject to the carrier-local wire limit; 2026-08-04
  Added the physical receiver and PMTU worker life cycle constraints during bare-UDP Link
  reconnection.

> Capacity field description: The historical `path_datagram_mtu` physical unit description in this
  RFC has been replaced by RFC-0037; RFC-0046 further deletes the path MTU field in OPEN. This RFC
  currently only defines LSA capacity, active circuit local transmission budget and carrier-local
  check.

## background

LSA propagates the converted `UserIpCapacity` of each directional physical link. The source node can
calculate the minimum value of the path based on this, but the old implementation does not bring the
result into the circuit, nor does it allow the relay to check the next hop capacity. Therefore,
topology delays, MTU changes, or out-of-synchronization will cause the relay to try to send Physical
Forward that exceeds the next hop upper limit. The old keepalive watchdog checks the receiving time
immediately after sending the keepalive, and will also misjudge a normal keepalive that has not been
scheduled by the dispatcher as an idle timeout.

## design

`OpenRequest` Using `path_inner_mtu:u16` (maintaining the original wire position), the source node
takes the minimum value in each direction of the complete path and incorporates it into the source
signature. Relay no longer saves the end-to-end capacity as a permanent forwarding ceiling; before
Physical Forward forwarding, the outgoing carrier performs an accurate pre-check based on the
current Physical frame, receive ID, and fake-TCP wire length. Frames exceeding the limit are
discarded and counted in the relay, and the carrier sending path is not called; the source is still
responsible for rejecting TUN packets according to `UserIpCapacity` and executing TCP MSS clamp. In
this way, the relay does not need to decrypt the end-to-end payload, and it can also ensure that
frames that exceed the next hop's capabilities will not be injected into the Physical Link.

The source saves `path_inner_mtu` when the active circuit is created. Topology refresh may be
completed before circuit reconstruction; within this window, the source routing MTU must be the
smaller value of the current topology calculation value and the upper limit of the active circuit.
It is prohibited to increase the TUN MTU above the relay binding due to newer (but not yet used for
this circuit) topology advertisements. The topology reconciler simultaneously compares the path
saved by the active circuit with the current preferred path and its capacity; when changes occur,
the old binding is first revoked and then OPENed again, so that the conservative initial detection
value can be restored after capacity convergence without permanently lowering the MSS. In this way,
the circuit remains conservative but transmittable before reconstruction, preventing the relay from
silently discarding large packets. Directly connected circuits have no relay binding and are not
rebuilt due to changes in local link detection values; when the candidate sequence contains
unavailable relays, the reconciler uses active paths that are still healthy to avoid meaningless
OPEN storms.

The shutdown threshold for Physical liveness becomes `idle_timeout + keepalive`. The tick that sends
the heartbeat no longer closes the Link with the old `last_rx` value at the same time, and reserves
a complete keepalive cycle for the asynchronous QUIC DATAGRAM to arrive at the dispatcher; it will
only be closed and reconnected if there is no authentication Physical payload. `Forward`,
`Keepalive`, `Probe` and `ProbeAck` are all authenticated Physical payloads. Receiving any form will
refresh the receiving active time; otherwise, periodic PMTU detection will suppress ordinary
keepalives, but will be mistakenly excluded from the liveness statistics, causing healthy links to
reconnect according to the idle deadline.

The physical receiver of Bare-UDP must also listen to the close event of the QUIC control
connection. After the control connection is closed, the receiver exits immediately, and the PMTU
worker must also be canceled; it cannot just wait for the UDP receive-id to be destructed, because
the receiver and PMTU worker themselves hold strong references to the Link. Otherwise, the new Link
after reconnection will share the underlying UDP port with the old Link, and the old Link will
continue to send probe frames using expired Physical session keys, causing the new Link to continue
authentication failure and periodic reconnection.

## Evolutionary boundaries with RFC-0022

RFC-0022 has separated the circuit ceiling from the relay's real-time carrier limit: the source
continues to use `path_inner_mtu` as the signature field, link establishment prompt, and its own
user IP sending limit; relay pre-checks Forward based on the current carrier wire limit before
assigning priority admission, physical seal, and physical serial number, and no longer saves the
OPEN value as a permanent forwarding ceiling. The wire field and signature input are unchanged.

## Security and Compatibility

The path capacity belongs to the OPEN state of the source signature, and the relay can only be
tightened but not expanded. Values   that are unknown or below the initial safe capacity are
rejected. The new OPEN wire body is incompatible with the old nodes, and the interconnection nodes
must be upgraded as a whole; the physical frame format and end-to-end encryption remain unchanged.
The relay's capacity check does not touch the inner IP plaintext.

## acceptance

- OPEN's path capacity field is round-tripped and signature tampering is rejected;
- The relay label is tightened according to the outgoing Link capacity;
- Physical Forward that exceeds the path capacity is discarded at the relay;
- Sending keepalives at the same time from both ends will not trigger idle close at the same tick;
- After the QUIC control connection is closed, the bare-UDP receiver and PMTU worker exit before
  reconnecting;
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  passed.
