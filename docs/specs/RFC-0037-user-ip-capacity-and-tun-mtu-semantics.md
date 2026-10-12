# RFC-0037: User IP Capacity and TUN MTU Semantics

- Number: RFC-0037
- Title: User IP Capacity and TUN MTU Semantics
- Status: Implemented
- Created: 2026-08-15
- Last updated: 2026-08-27

> RFC-0046 supersedes this RFC's OPEN capacity-field definition: current OPEN no longer carries
  `path_inner_mtu`. This RFC still defines LSA `inner_mtu`, active-circuit local send budgets, and
  carrier-local wire checks.

## Background and Problem

Tinect currently uses four capacities: underlay IP MTU, QUIC DATAGRAM payload, bare Physical frame
capacity and TUN inner IP MTU. They have different meanings on different carriers, but they are
mainly represented by names such as `datagram_mtu`, `path_datagram_mtu` and `send_budget` in the
code, resulting in the same value being repeatedly added or subtracted in different layers for
encapsulation overhead.

The current final data plane behavior of `tun.mtu` is close to regular TUN semantics: it restricts
complete user IP packets, excluding Tinect encapsulation. However, LSA and Circuit budget still
mainly use Physical DATAGRAM units; the source then adds `tun.mtu` to the end-to-end DATA and
Physical Forward overhead, and the relay and carrier handle their own outer layer overhead
respectively. This model is not suitable for mixing `quicfull`, bare UDP and fake-TCP carriers, and
is also prone to false capacity due to repeated deduction of receive ID or QUIC headers.

Additionally, the end-to-end DATA fixed overhead in the current implementation code is 41 bytes:
`circuit_id[16]`, `sequence[8]`, `direction[1]` and AEAD tag[16]. Some protocol documents are still
written as 40 bytes and must be revised simultaneously.

## Goals and Non-goals

### Target

- Make it clear that `tun.mtu` represents the maximum length of the complete user IPv4/IPv6
  packet, excluding Tinect's own encapsulation.
- Define a unified `UserIpCapacity`, which represents the maximum user IP packet length that a
  path can carry.
- Let the carrier locally translate differences in transport protocols, address families, QUIC
  DATAGRAM budgets, bare receive IDs, and fake-TCP outer layers.
- Let LSA, path calculation and source sending budget use the same user IP unit.
- Preserves the boundary that the relay does not decrypt the end-to-end payload; the final
  security boundary of the relay is still the current verifiable Physical wire limit of the
  outgoing carrier.
- Avoid duplication of deductions for Tinect encapsulation, bare UDP receive ID, and QUIC outer
  overhead.
- Keep the transmission tight immediately when the capacity decreases, and do not rebuild the
  circuit due to capacity changes when the capacity increases.

### Non-goals

- This RFC does not introduce Tinect fragmentation, reassembly, or reliable retransmission.
- This RFC does not remove end-to-end AEAD, Physical AEAD, sequence, or replay protection.
- This RFC does not change the security boundary of relay not decrypting user IP payloads.
- The first phase of this RFC does not implement DATA batching of multiple packets; this requires
  independent wire format and delay policy evaluation.
- This RFC does not expose the underlay MTU as user-configured `tun.mtu`.

## Terminology and Capacity Units

Let `N` be the full user IP packet length, including the user's own IP, TCP, UDP or other transport
headers.

### UserIpCapacity

`UserIpCapacity` is the full user IP packet capacity without Tinect encapsulation. It is:

- Configuration semantics of `tun.mtu`;
- The link capacity propagated in the LSA;
- The unit of path calculation and circuit source sending budget;
- Path MTU input for TCP MSS clamp.

### CircuitFrameCapacity

The maximum length of the end-to-end DATA frame. Ordinary packets are:

```text
N + optional_fake_ip_envelope + 41
```

The end-to-end fixed overhead of 41 bytes is given by:

```text
circuit_id[16] | sequence:u64 | direction:u8 | AEAD tag[16]
```

composition. FakeIP envelope is 6 bytes for IPv4 and 18 bytes for IPv6. It only exists in secure
domain name routing with FakeIP enabled.

### PhysicalFrameCapacity

The maximum length of the Physical Forward frame, excluding the additional receive ID of the bare
carrier. Forward adds 25 bytes at each hop:

```text
form:u8 | physical_sequence:u64 | physical_tag[16]
```

Therefore, the Physical frame length of a normal FakeIP packet is `N + 66`.

### CarrierWireLimit

The final wire length limit submitted to the specific carrier. It can additionally contain:

- 4-byte `destination_receive_id` of bare UDP data plane;
- fake-TCP’s IPv4/IPv6, TCP base headers and Timestamp option;
- QUIC packet, DATAGRAM frame and QUIC AEAD overhead for full QUIC.

These differences can only be calculated by the carrier based on actual protocols and address
families, and must not be guessed at by the domain layer.

## Overhead and boundaries of each layer

The relationship between ordinary FakeIP packets is:

```text
Circuit frame       = N + 41
Physical frame      = N + 41 + 25 = N + 66
Bare carrier wire = N + 66 + 4 = N + 70
```

`Connection::max_datagram_size()` of full QUIC is already the upper limit of application payload
that can be passed to `send_datagram()`, and the QUIC packet related overhead cannot be deducted
again at the upper layer. It is not in the same unit as Quinn's DPLPMTUD path-payload cap: current
conservative 1-RTT calculations subtract at most 38 bytes (flags, 8-byte connection ID, 4-byte
packet number, 16-byte AEAD tag, and DATAGRAM frame header). Therefore, on the standard 1500-byte
Ethernet path, the upper limit of path-payload of native IPv4/IPv6 is 1472/1452 respectively, while
the upper limit of full QUIC application DATAGRAM is 1434/1414 respectively; the upper limit of
path-payload of fake-TCP is 1448/1428, and the upper limit of application DATAGRAM is 1410/1390. The
DPLPMTUD configuration uses the former, and the `Connection::max_datagram_size()` release uses the
latter. The two cannot be mixed in capacity tables or tests. The PMTU results of the bare UDP
carrier are uniformly exposed as the Physical frame capacity, and the receive ID is only increased
once during the carrier wire check.

Physical Forward's 40-byte metadata is an alternative to the existing circuit metadata in the
end-to-end frame, and is not an additional 40-byte burden. relay regenerates Physical metadata,
Physical sequence, and Physical tag at each hop, but forwards the end-to-end ciphertext unchanged.

The fixed Physical payload of Physical Keepalive is 25 bytes; the bare carrier still adds an
additional 4-byte receive ID. The Probe/ProbeAck of the bare carrier continues to use the
`target_len` and `physical_frame_len` conversion specified in RFC-0014, but the externally released
link capacity is converted to `UserIpCapacity`.

## design

### 1. The carrier is responsible for protocol difference conversion

The carrier internally retains and uses `PhysicalFrameCapacity` and `CarrierWireLimit` for final
sending check. Link provides:

```text
user_ip_capacity =
    physical_frame_capacity - 41 - 25
```

Carrier-specific processing must be done before this step:

- full QUIC uses Quinn's current DATAGRAM payload capacity;
- For bare UDP, first deduct the bare data plane receive ID to obtain the Physical frame capacity;
- fake-TCP calculates the outer upper limit based on actual IPv4/IPv6 and established TCP options;
- QUIC packet and DATAGRAM frame overhead are only handled by Quinn's capacity calculation.

All subtractions must be done through shared pure functions, and splicing bare constants in path,
topology, or Circuit code is prohibited.

### 2. LSA and path calculation

The `LinkMetric` capacity field of the LSA is changed to `inner_mtu`, and the unit is
`UserIpCapacity`. The field is still `u16`, but the field semantics have changed, so the RFC-0037
implementation requires an overall upgrade of the connected nodes.

The source node takes the minimum value of `inner_mtu` for the complete path edge by edge. The first
hop reads the real-time `UserIpCapacity` of the local link, and the subsequent hop reads the
`inner_mtu` of the signed LSA. Path calculation no longer calls `inner_mtu_from_datagram_limit()`,
and Tinect or receive ID overhead is no longer deducted repeatedly.

### 3. OPEN and Circuit budget

The current OPEN for RFC-0046 does not carry path MTU or other capacity fields. The active circuit's
initial sending budget is still calculated locally by the source node:

```text
min(configured_tun_mtu, path_user_ip_capacity, circuit_ceiling)
```

`send_budget` Save `UserIpCapacity`. Source checks before entering the encrypted send queue:

```text
user_packet_len + fake_ip_envelope_len <= send_budget
```

The encryption layer and carrier must still perform independent checks on the final circuit frame,
physical frame, and carrier wire length; the source budget is not the final wire security boundary.

relay does not use the OPEN field as a permanent forwarding ceiling. The relay continues to
pre-check according to the current Physical wire limit of the outgoing carrier before priority
admission, physical seal and sequence number allocation. The actual carrier sending check is still
the final authority.

### 4. TUN and FakeIP

The actual TUN MTU at runtime is the minimum value of the configured upper limit and the current
active path `UserIpCapacity`. The configured `tun.mtu` is not pre-reduced for Tinect packaging.

The FakeIP envelope is an optional extra field in the end-to-end payload and does not change the
meaning of `tun.mtu`. The specific route using FakeIP deducts the actual envelope length when MSS
clamp and source send checks; the ordinary route should not suffer a global loss of 18 bytes due to
the existence of IPv6 FakeIP configuration in the system.

The first stage retains the conservative behavior of the current global TUN projection; later, the
impact of a small-capacity path on other paths can be reduced through route-specific MTU/ADVMSS, but
not at the expense of relaxing the final data plane guard.

## security impact

- LSA capacity is still signed by origin, and tampering, replay, and expiration processing remain
  unchanged.
- The sending budget of active-circuit is only a local limit and does not replace OPEN signature,
  relay authorization or `EgressPolicy::authorize()`.
- The relay will not bypass the final wire check of its own carrier due to the local end-to-end
  capacity status of the source node.
- Any unknown circuit, error physical frame, over-limit frame and unauthenticated data are still
  handled according to the existing fail-closed semantics.
- `UserIpCapacity` only sends budget tips and does not replace `EgressPolicy::authorize()`, nor
  does it change end-to-end or hop-by-hop authentication.

## Compatibility and migration

This is a semantic change to the LSA capacity field. LSA's `inner_mtu` still requires the entire
connected node to be upgraded; the compatibility of the OPEN format is also specified by RFC-0046,
and it cannot be deployed mixed with the old Circuit control wire.

Migration order:

1. All nodes are upgraded to a version that supports RFC-0037;
2. Confirm that the capacity units in LSA, active budget, status, and logs are all user IP bytes;
3. Then enable the larger `tun.mtu` which depends on the new capacity;
4. Observe `packet:exceeds_path_mtu`, carrier wire oversize, PMTU degradation and capacity
   generation.

No compatible interpretation of the old `datagram_mtu` semantics is provided, nor is automatic unit
guessing preserved.

## Implementation and test acceptance

### Unit testing

- Assert that the end-to-end DATA overhead is 41, the Physical Forward overhead is 25, and the
  total Tinect Forward overhead is 66;
- Test `UserIpCapacity ↔ PhysicalFrameCapacity` bidirectional conversion and insufficient capacity
  saturation behavior;
- Covers carrier capacity conversion of full QUIC, bare UDP, and fake-TCP IPv4/IPv6;
- Assert that the bare receive ID appears only once in the carrier wire check;
- Covers FakeIP IPv4 6-byte, IPv6 18-byte envelope;
- Assert source UserIp budget, Circuit frame guard and carrier wire guard respectively to take
  effect.

### Real network test

- Direct and three-node multi-hop paths;
- QUIC full, bare UDP, fake-TCP, and IPv4/IPv6 combinations;
- underlay MTU rise, fall, black hole recovery, Link replacement and downstream restart;
- UDP/ICMP over-limit reject and IPv4/IPv6 TCP MSS clamp;
- Boundedconvergence is maintained even when control plane capacity is lost, duplicated, late, and
  out of order;
- At the end of the test, confirm that namespace, TUN, routing and firewall resources are all
  cleared.

## Open Questions

- Whether route-specific MTU/ADVMSS should be added in the subsequent In Progress of this RFC, or
  whether the RFC should be created separately;
- Delay, congestion and replay boundaries for small packet DATA batch/superframe.

## Implementation Notes

- The conversion of UserIpCapacity to Physical frame is defined in the `src/mtu.rs` set and is
  based on a fixed overhead of 66 bytes of 41 bytes of DATA + 25 bytes of Physical Forward.
- Quinn's path-payload upper limit and application DATAGRAM upper limit have been separated; full
  QUIC's Link directly consumes `Connection::max_datagram_size()`, while DPLPMTUD only uses the
  path-payload upper limit.
- LSA `inner_mtu`, capacity vector, Circuit send budget, route binding, and capacity events have
  been unified into user IP bytes; Physical PMTU state remains internal to the carrier, and bare
  receive-id, QUIC DATAGRAM, and fake-TCP differences are handled at Link boundaries.
- RFC-0046 has deleted the capacity field of OPEN; `docs/protocol.md` and related historical RFCs
  have been synchronized, but LSA `inner_mtu` still requires an overall upgrade of the entire
  network.
- Acceptance: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` and
  `cargo test` all passed; unit tests cover 219 library tests and 27 binary tests.
