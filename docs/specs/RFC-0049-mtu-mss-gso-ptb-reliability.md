# RFC-0049: MTU/MSS/GSO/PTB reliability fix (hybrid KEX stall)

- Number: RFC-0049
- Title: MTU/MSS/GSO/PTB Reliability Fix (Hybrid KEX Stall)
- Status: Implemented
- Created: 2026-09-11
- Last updated: 2026-09-11

## Background and Problem

User reports: OpenSSH connections via Tinect reliably stall (stuck at `expecting
SSH2_MSG_KEX_ECDH_REPLY`, eventually timing out) when negotiating the default post-quantum hybrid
KEX `mlkem768x25519-sha256`, while forcing `KexAlgorithms=curve25519-sha256` succeeds immediately.

On-site information:

- The `tinect0` MTUs at both ends are 1354 and 1114 respectively (the MTUs are inconsistent).
- Packet capture shows client SYN MSS 1452 (larger than the smaller TUN MTU) and other end SYN-ACK
  MSS 1054.
- SACK `{2737:2927}` occurs during KEX (the back segment arrives first and the front segment is
  missing), followed by retransmission and stalling.
- `tinect0` at both ends are `TSO off / GSO on / GRO on` and `net.ipv4.tcp_mtu_probing=0`.

Three types of mutually amplifying defects identified during the investigation:

1. **MSS clamping uses snapshot period copies instead of real-time budgets. ** The sending path
   uses `SecureRoute.mtu` (a copy of `send_budget` at the snapshot) to calculate `effective_mtu`,
   and the sending admission uses the real-time `send_budget`. When the first hop PMTU drops
   through `update_active_link_capacity`, the fast path immediately tightens `send_budget` and
   wakes up the route refresh, but in the window before the next snapshot reconstruction
   `binding.mtu`, the new SYN will negotiate the MSS according to the old large MTU, and
   subsequent sending checks according to the new budget will discard the full-size segments sent
   according to this MSS. Once negotiated, the MSS remains unchanged for the life of the
   connection, so a handshake that falls within the window will cause the entire connection to
   continue to blackhole; smaller classical-KEX messages (which can be accommodated in a single
   segment) can still pass through, while larger hybrid-KEX replies (which require multiple full
   MSS segments) are reliably triggered.

2. **TUN GSO/GRO superpackets are silently discarded. ** The default value for a new TUN is
   `generic-segmentation-offload: on / generic-receive-offload: on` (exactly consistent with the
   report). The kernel can deliver GSO super packets larger than the TUN MTU and larger than the
   coverage path budget to the user mode at one time. The data plane treats each TUN read as a
   complete inner IP packet and directly determines it according to `size + envelope <=
   send_budget `. Exceeding packets are discarded with ` packet:exceeds_path_mtu` without any
   feedback. Uppercase operations (such as several KB of KEX replying to a single `write`) are
   more likely to trigger GSO merge, while small messages are not triggered, showing an
   "algorithm-related" stall.

3. **Oversized packets are dropped silently and without PTB. ** After the coverage path budget
   decreases, the large segment of the established connection (sent according to the old MSS)
   will be discarded at the source with `packet:exceeds_path_mtu`, but ICMP Fragmentation-Needed
   / Packet-Too-Big will never be sent back to TUN. The sender will always retransmit the same
   size at `tcp_mtu_probing=0` and cannot converge. TUN MTU reduction by itself cannot repair the
   existing socket that has cached `dst MTU`. A PTB is required to allow the kernel to reduce the
   routing MTU and retransmit the small segment.

## Goals and Non-goals

### Target

- MSS clamping uses the same real-time budget as TUN MTU projection, eliminating snapshot window
  misnegotiation.
- TCP GSO superpackets are segmented in user mode according to the real-time effective budget, so
  that uppercase operations are no longer discarded as a single superpacket (new TUN still tries
  to turn off offload with best-effort, and only warns when the driver does not support it).
- When the source discards oversized inner packets, it sends back a rate-limited ICMP PTB (IPv4
  Frag-Needed / IPv6 Packet-Too-Big) to the TUN, carrying a real-time effective budget to converge
  the existing TCP/UDP sender.
- Integrated test coverage with different underlay/TUN MTU: internal capacity status,
  bidirectional MSS, PTB loopback, offload status, large packet transmission.

### Non-goals

- Does not introduce Tinect fragmentation/reassembly or reliable retransmission (still the
  responsibility of end-to-end TCP).
- No changes to end-to-end AEAD, hop-by-hop authentication, sequence/replay, ACL, or relay
  non-decryption boundaries.
- Does not rely on ICMP PTB to penetrate NAT/firewall to reach the opposite end; PTB is only local
  TUN feedback, MSS clamping is still the primary mechanism, and PTB is the backbone of existing
  connections.
- Do not enable VNET_HDR/GSO transparent transmission on TUN; in the first stage, user-mode TCP
  segmentation + non-TCP PTB convergence is used in exchange for correctness. If performance is
  required in the future, separate RFC evaluation will be conducted.

## Terminology and Capacity Units

Following RFC-0037's `UserIpCapacity` (complete user IP packet, excluding Tinect encapsulation) and
66-byte fixed overhead (end-to-end DATA 41 + Physical Forward 25). This RFC adds:

- **Real-time budget**: `ActiveCircuit.send_budget` (`Arc<AtomicUsize>`), both fast paths and LSAs
  can be tightened, and `SecureRoute.mtu` of the routing snapshot is just a copy of it.
- **Effective MTU**: `send_budget - fake_ip_envelope` (ordinary routing envelope is 0), that is,
  the number of inner bytes advertised by MSS clamping and PTB.
- **TUN projection**: Runtime TUN MTU = `min (real-time budget) ∩ configuration upper limit -
  FakeIP global reservation`, the same as before, but the input is changed from snapshot copy to
  real-time budget.

## design

### 1. MSS clamp uses real-time budget (`src/dataplane.rs`)

The sending path is loaded `send_budget` once per packet, and the same value is used for:

```text
effective_mtu = send_budget - envelope
clamp_mss(packet, effective_mtu)
reject if size + envelope > send_budget
```

A single load ensures that the clamping and discarding decisions of the same packet are consistent,
and there is no "clamping based on the old value and discarding based on the new value". FakeIP
routing subtracts the actual envelope, and ordinary routing is not affected by global IPv6
reservation (consistent with RFC-0037).

### 2. TUN MTU projection uses real-time budget (`src/daemon/application.rs`)

When the route refresh cycle calculates `route_mtu`, `send_budget.load()` is read instead of
`route.mtu` copy for each binding, and then the value is reduced with `configured_tun_mtu` and the
FakeIP global reservation is deducted. After the first-hop fast path tightens the budget, even if
the snapshot has not been rebuilt, the next refresh that is awakened (the fast path is `notify`) can
immediately see the new budget and lower the TUN MTU, and the new kernel connection negotiates the
MSS according to the small MTU.

### 3. TUN GSO super packet is segmented in user mode (`src/dataplane/packet.rs` + `src/dataplane.rs`)

The default for new TUN is `generic-segmentation-offload: on`, and the legacy
`SIOCETHTOOL/ETHTOOL_SGSO` ioctl returns `EOPNOTSUPP` on some TUN drivers (modern `ethtool` is set
by netlink), so offload cannot be relied on. `create_tun` still tries ioctl with best-effort (if
successful, the kernel will move the segmentation point forward, if it fails, only a warning will be
given). The correctness is guaranteed by user mode segmentation:

`segment_tcp_gso(packet, effective_mtu)` Pure function divides TCP data superpacket
(non-SYN/RST/URG, with payload, and header can be accommodated) into multiple MSS segments according
to `effective_mtu`, copies the IP/TCP header (including options and extension headers), increments
the IPv4 ID and TCP sequence number, keeps PSH/FIN only in the last segment, and recalculates the
double checksum. Each segment is `<= effective_mtu`, so `segment length + envelope <= send_budget`
can be sent segment by segment through the same sending worker (the worker still has a real-time
budget recheck as a final guard before dequeuing).

Non-TCP jumbo packets are not fragmentable (fragmentation is not supported) and fall into the PTB
path described below. This allows uppercase operations (such as multi-KB KEX replies to a single
`write`-triggered GSO merge) to no longer be dropped as a single superpacket, while the small
message path remains unchanged, essentially eliminating "algorithm-related" stalls.

### 4. Oversized packet return speed limit PTB (`src/dataplane/packet.rs` + `src/dataplane.rs`)

`build_ptb_for_oversize(original, mtu)` is a pure function:

- IPv4: Outer 20 bytes IP (src=original dst, dst=original src, proto=ICMP) + ICMP type 3 code 4 +
  Next-Hop MTU=`mtu` + original IP header + 8 bytes, double checksum correct.
- IPv6: outer 40 bytes IP6 (src=original dst, dst=original src, next=58) + ICMPv6 type 2 code 0 +
  MTU=`mtu` (32 bits) + the first 48 bytes of the original packet, including the pseudo header
  checksum.
- Returns `None` for fragments, ICMP error messages themselves, and malformed headers to avoid
  loops and amplification.

The send path is looped back on the `packet:exceeds_path_mtu` branch:

- MTU takes the real-time `effective_mtu` of the same packet (envelope deducted).
- The global maximum is 1 every 200ms (5/sec), which is enough to support PMTUD (1 per RTT) and
  fix the upper bound of reflection amplification.
- Write the PTB packet to TUN through the same `tx_device` and increment `tun_tx`. If the write
  fails, stop processing this TUN packet, consistent with the existing behavior. A single PTB write
  failure must not interrupt the worker; when the PTB is written successfully, the original packet
  is still dropped.

Security: PTB is only sent to the original src (local kernel routing determines the destination),
does not forward across coverage, and does not carry the key; the speed limit makes the
amplification of the local forged source negligible; but `EgressPolicy::authorize()` is not changed,
and the relay still does not decrypt it.

## security impact

- LSA signature, OPEN authorization, `EgressPolicy`, and authentication encryption remain
  unchanged.
- PTB does not propagate across links, does not change the wire format, and does not introduce a
  new control plane that can be forged by the remote end; the only cross-border effect is the
  downward adjustment of the local kernel routing MTU (standard PMTUD semantics).
- Turning off offload does not relax any guard, but only moves the kernel segmentation point
  forward (when ioctl is supported); user-mode TCP segmentation also does not relax the guard, and
  each segment is still subject to real-time budget and carrier wire checks; end-to-end and
  carrier triple length checks (UserIp budget / Circuit frame / carrier wire) remain unchanged.
- The rate-limiting PTB does not replace the fail-closed semantics of admission rejection and is
  only a local diagnostic/convergence signal.

## Compatibility and migration

- on the wire The wire format remains unchanged and can be rolled out; old nodes have no PTB, no
  user mode segmentation, and can still communicate (only the old stall window is retained).
- After the upgrade, `ethtool -k` may still display GSO/GRO on (depending on whether the driver
  supports ioctl shutdown), but this does not affect the correctness: TCP super packets have been
  fragmented in user mode, and UDP super packets still go through PTB convergence.
- The TUN MTU semantics remain unchanged (still `min(config, path) - FakeIP reserved`), but
  convergence is faster; an established TCP connection will receive the PTB for the first time
  after the path drops and retransmit the small segment (an observable retransmission), which is
  expected behavior.

## Implementation and test acceptance

### Unit testing

- `user_ip_capacity` conversion, FEC, carrier table (existing, RFC-0037) remains passed.
- Added `build_ptb_for_oversize` forward (IPv4/IPv6 MTU, address swap, double checksum) and
  rejection (fragmentation, ICMP errors, loopback, truncation) tests.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  passed.

### Real network test (`tests/remote_mtu_mss_ptb_gso.sh`, new)

- Three nodes (A-B 1500, B-C 1280) + heterogeneous TUN configuration (A 1354, C 1114, recurrence
  report), QUIC direct path.
- Record three terminals `ethtool -k` offload state (informational; the driver does not support
  ioctl and is still on when closed. The correctness is guaranteed by user mode TCP segmentation,
  and off is not forced to be asserted).
- assertion `status` of `datagram_max_size` In order (A-B > B-C)   and the TUN MTU follows the path
  (A's TUN has been brought down from the configuration).
- Bidirectional MSS: A→C injects SYN of MSS 1452 (reported value), pcap expects to be clamped to
  `min(AB,BC)-66-20-24`; C→A injects SYN of MSS 1460, reverse clamps to C's own budget.
- PTB: Construction, loop suppression and FakeIP pre-translation addresses are covered by the
  `dataplane::packet` single test; the shell no longer injects large UDPs through the kernel
  (cross-runner cache routing behavior is unstable, see script comments), so there is no
  one-to-one correspondence between assertions of `acl_rejections["packet:exceeds_path_mtu"]`
  growth and "no sustained growth".
- Large packet TCP (such as 20KB single write, simulating KEX amplification form) is still
  successful when GSO is turned on (user mode segmentation takes effect; if the driver supports
  ioctl shutdown, the kernel moves the segmentation point forward, either of the two is true),
- Fault injection: Shrink the downstream B-C underlay MTU from 1280 to 1200 during operation, and
  assert capacity, TUN, and fresh MSS converge within the bounded time (after shrinking, bulk will
  not be hard asserted temporarily due to the variable cross-platform behavior of the kernel
  routing cache, and will be completed with the deterministic TUN writer).
- Cleanup: namespace, TUN, routing, firewall, socket all cleaned up.

## Open Questions

- Is it necessary to expose the PTB sending count and rate-limited discard count in
  `status`/Prometheus so that "notified sender" and "silent discard" can be distinguished during
  troubleshooting?
- The performance tradeoff of overpacket segmentation in user mode (rather than turning off
  offload) will be discussed in a separate RFC when there are clear throughput requirements.
- The 48 bytes embedded in the PTB under the IPv6 extension header path may not include the
  transmission port. The peer may not be able to associate the socket and ignore the PTB; it is
  currently regarded as a security downgrade (no harm). Whether the extension header needs to be
  parsed to embed the port needs to be evaluated.

## Implementation Notes

- `src/dataplane.rs`: Clamp and discard the same real-time `send_budget`; when the budget is
  exceeded, the PTB is sent back at a limited rate.
- `src/dataplane/packet.rs`: Added `build_ptb_for_oversize` pure function and single test.
- `src/daemon/application.rs`: TUN projection takes real-time budget.
- `src/platform.rs` (Linux): `create_tun` best-effort attempts ioctl to close GSO/GRO/TSO (some
  drivers return EOPNOTSUPP with only a warning, correctness is guaranteed by userland
  segmentation).
- Added `tests/remote_mtu_mss_ptb_gso.sh` and added CI `network-integration` matrix.
- Acceptance: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test` passed; the privileged integration test passed under the same underlay/TUN
  heterogeneity.
