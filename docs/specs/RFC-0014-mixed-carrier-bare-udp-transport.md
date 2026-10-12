# RFC-0014: mixed-carrier bare-udp transport

- Number: RFC-0014
- Title: mixed-carrier bare-udp transport
- Status: Implemented
- Created: 2026-07-26
- Last updated: 2026-08-27
- Change record: 2026-07-26 Review revision - Clarify Hello global `receive_id`, configuration
  migration table, bare UDP pathless migration, cross-reference with fake-TCP RFC and common port
  sending suggestions; 2026-08-03 Clarify RFC-0022 Implemented, only replace PMTU search state,
  do not replace capacity unit and Probe wire constraints; 2026-08-05 Clarify that local UDP
  sending errors must be classified according to errno. `EMSGSIZE` can only enter the PMTU excess
  path, and `EAGAIN/ENOBUFS` can only enter the local queue pressure path and must not be recorded
  as a protocol error; 2026-08-07 Repair the NAT mapping conflict caused by the active dial-up
  multiplexing listener port, and clarify the temporary port and life cycle of the active client
  endpoint; 2026-08-15 According to RFC-0037, clarify the boundary between carrier-local Physical
  frame and external `UserIpCapacity`.

> Current capacity semantics: This RFC's `target_len`, `physical_frame_len` and bare carrier wire
  checks are still valid; `LinkCapacityChanged`, LSA `inner_mtu` and path/TUN budgets are
  uniformly published as full user IP bytes per RFC-0037. RFC-0046 has deleted `path_inner_mtu` in
  OPEN; the old `Link::max_datagram_size()`/`datagram_mtu` expression in this article only refers
  to the carrier-local Physical frame capacity, not the externally transmitted user IP capacity.

## Background and Problem

Currently, there are only `quic://` and `quicp://` carriers: the former puts both QUIC stream and
QUIC DATAGRAM on ordinary UDP, and the latter encapsulates all UDP-shaped datagrams seen by Quinn as
fake TCP. The physical layer AEAD is located within QUIC DATAGRAM, so the data planes in both modes
have two layers of encryption, QUIC TLS and Physical AEAD.

It is necessary to support both the full QUIC data plane and the "QUIC stream + bare UDP data plane"
options, and allow fake TCP to work on either option. Nodes must also be able to listen to one
carrier and actively connect to peers using another carrier; the scheme of the local listener can no
longer be regarded as a global carrier constraint.

When bare UDP and QUIC reuse ports, Quinn and the bare data plane must reliably distinguish inbound
packets. QUIC fixed bit could have been used for this purpose, but Quinn allows greasing by default,
so disabling greasing must be defined as a protocol invariant. Bare UDP is no longer directly
carried by Quinn's DPLPMTUD and must have independent authentication PMTU detection and black hole
recovery.

## Goals and Non-goals

Target:

- Define four clear, fallback-free carrier schemes.
- Allows the listener to select a scheme independently for each peer endpoint.
- Securely offload QUIC and bare UDP on the same UDP or fake-TCP logical port.
- Physical AEAD is retained so that bare UDP is a single layer of end-to-end adjacency encryption
  rather than a clear text data plane.
- Provides one-way, dynamic, propagable PMTU capacity for bare UDP.

Non-goals:

- Interoperate with the old `quic://` or `quicp://` node.
- Downgrade bare UDP to plain UDP fallback, or fake TCP behavior on non-Linux platforms.
- Replace Tinect authentication and Physical AEAD with socket address, bare UDP receive ID, or
  QUIC TLS.
- Modify the encryption structure of circuit DATA or Physical Forward in this RFC; this change is
  specified separately in RFC-0015.
- Implement QUIC-style connection migration, source-port/address migration, or silent recovery
  after NAT rebinding for bare UDP data plane (see "Path and Source Binding" below).

## Carrier and configuration semantics

The scheme of the endpoint URL is precisely defined as follows:

| scheme | QUIC stream | physical datagram | on the outer layer of the wire |
| --- | --- | --- | --- |
| `quicfull://` | QUIC | QUIC DATAGRAM | UDP |
| `quic://` | QUIC | Physical frame in bare UDP | UDP |
| `quicfull-faketcp://` | QUIC | QUIC DATAGRAM | fake TCP |
| `quic-faketcp://` | QUIC | Physical frame in bare UDP logical packet | fake TCP |

### Configuration migration (hard upgrade)

This RFC **flips** existing data plane semantics of `quic://` and discards the `quicp://` name.
Nodes with unchanged configuration will be disconnected from the old semantic nodes after upgrade,
and may be silently switched to the bare UDP data plane. The implementation and release notes must
pin the following table; when configuration loading encounters a rejected scheme, it must fail and
give a clear replacement prompt.

| Configuration before upgrade | If you want "unchanged behavior" after upgrade | If you want to accept the new default after upgrade |
| --- | --- | --- |
| `quic://` (QUIC stream + QUIC DATAGRAM) | **`quicfull://`** | `quic://` (becomes bare UDP data plane) |
| `quicp://` (QUIC stream + QUIC DATAGRAM over fake TCP) | **`quicfull-faketcp://`** | No further writing allowed `quicp://` |
| (no old counterpart) Bare UDP + fake TCP | — | `quic-faketcp://` |

`quicp://` is rejected, the error message must prompt to use `quicfull-faketcp://` (retaining the
full data plane) or use `quic-faketcp://` when a bare data plane is clearly needed. The old
`quic://` literal uses **bare UDP** semantics after upgrade; deployers must explicitly change to
`quicfull://` if they want to retain the original full QUIC DATAGRAM behavior.

`listen` Only select carriers that accept inbound QUIC connections, and the listener port is used
only for inbound connections. `peers.*.endpoints` points to the remote listener, so it can be
different from the local `listen`. Each peer's active dial-up (including reconnection) must create
an independent client endpoint based on the resolved remote address, and bind the temporary local
port with `outbound_bind_address(...):0`; release the endpoint after dial-up failure, and try to
reallocate the port next time. After success, the endpoint will remain until the corresponding link
is closed. This rule applies to four schemes, and the listener endpoint will not be reused because
the outer carrier or address family is the same as the listener. For `quic://` or `quic-faketcp://`,
the QUIC stream and raw UDP data plane of the same client endpoint must use the same I/O object, the
same port, and the same path.

The two fake-TCP schemes only support Linux and continue to be subject to raw socket, RST guard,
`CAP_NET_RAW`, and `CAP_NET_ADMIN`; explicit configuration of `fwmark` is supported, but
`carrier_interface` is not supported. Fake-TCP appearance, handshake recovery, and middlebox-related
behaviors still follow RFC-0010 and RFC-0013; this RFC only defines scheme and offloading, and does
not relax those invariants.

## Same port distribution and receiving ID

All Tinect-created Quinn client/servers `EndpointConfig` must have `grease_quic_bit(false)` set and
`supported_versions` fixed to QUIC v1 only (`0x00000001`). Tinect does not support QUIC Version
Negotiation: the peer with mismatched versions fails to establish a link and does not negotiate an
alternative version. In this way, the first byte bit 6 of the QUIC packets sent and received by
Tinect and handed over to Quinn in this protocol are all `1`; the Version Negotiation packet does
not belong to the acceptable carrier input.

When receiving ordinary UDP datagrams or fake-TCP decapsulated logical datagrams:

1. Packets whose first byte bit 6 is `1` are only delivered to Quinn.
2. Packets whose first byte bit 6 is `0` are only parsed according to the Physical frame when the
   first byte is the bare UDP form registered in RFC-0015 and will never be handed over to Quinn;
   other packets (including Version Negotiation) are silently discarded.

Select the correct Physical receiving state for O(1), and each endpoint assigns a non-zero `u32
receive_id` to each **Physical Link** (including full and bare carriers). A value of zero is illegal
in Hello, HelloAck, and bare UDP headers. The ID is a receive orientation value in the endpoint's
local namespace, not an identity, key, or authorization credential; the allocator must avoid
collisions with currently active mappings, refuse to establish new Links when exhausted, and cannot
randomly guess or overwrite old mappings.

**Hello / HelloAck wire format is unified for all four schemes**: they always carry and sign
non-zero `sender_receive_id`. The full carrier must also allocate and exchange this field so that
the identity layer and wire have only one parsing path. The QUIC DATAGRAM payload of the full
carrier still does not attach the `destination_receive_id` header; only the bare UDP common headers
of `quic://` and `quic-faketcp://` carry the `destination_receive_id` of the opposite end and are
delivered through table lookup. A full-only deployment still pays for the 4-byte ID field in the
Hello, but does not use this mapping for demux in the data plane.

The integers of Hello and HelloAck are big-endian, and the body and signature inputs are precisely
defined as follows. The `sender_receive_id` of each message is the ID assigned by the party sending
the message to itself for receiving (when bare UDP is used):

```text
Hello body:
  node_id:bytes[16] | public_key:bytes[32] | link_nonce:bytes[32] |
  sender_receive_id:u32(be) | signature:bytes[64]
Hello signature input:
  node_id | public_key | link_nonce | sender_receive_id

HelloAck body:
  node_id:bytes[16] | public_key:bytes[32] |
  sender_receive_id:u32(be) | signature:bytes[64]
HelloAck signature input:
  node_id | public_key | sender_receive_id | hello_link_nonce:bytes[32]
```

Therefore, the signature of HelloAck is bound to the ID of the receiver and the Hello nonce at the
same time; the signature of Hello is bound to the ID of the initiator. After successful
authentication and `accept_connections` authorization, the receiver assigns and registers its own
ID, and issues HelloAck. The client must verify the HelloAck's identity, signature, and
`hello_link_nonce` before registering its own mapping. For bare carrier: The bare UDP data plane
is enabled only when the authentication of both parties is successful, both parties obtain the peer
ID, and the local mapping is registered. For full carrier: ID exchange and mapping registration are
also completed, but the data plane still only uses QUIC DATAGRAM. The mapping must be unregistered
immediately upon shutdown, authentication failure, or when the Link is replaced by concurrent
dialing.

### Path and source binding

The source address/port of the bare UDP packet must be consistent with the remote underlay address
currently recorded by the Link, otherwise it will be silently discarded. This RFC does not provide
for bare UDP:

- QUIC connection migration or preferred address;
- Automatically migrate the mapping to the new quadruple after NAT rebinding;
- Multipath coupled with Quinn path verification.

If NAT or routing causes the source quad to change, the QUIC stream may still be restored by Quinn,
but the raw data plane remains unavailable until Hello/Link authentication is re-completed and the
remote address is refreshed. Implementations must not falsely report "QUIC Still Connected" as bare
UDP Link health.

The public header for bare UDP is:

```text
physical_form:u8 | destination_receive_id:u32(be) | physical_sequence:u64 | physical_payload
```

Bit 6 of `physical_form` must be `0`. `physical_sequence` and `physical_payload` are defined by
RFC-0015; full carrier does not carry `destination_receive_id`. Unknown forms, truncated packets,
unknown IDs, unauthenticated/closed links, or sources that do not match the current remote address
of the link are all silently discarded. ID only to avoid link-by-link attempts to Physical AEAD;
actual origin, identity, integrity, and replay checks are still done by Physical AEAD.

## Bare UDP PLPMTUD

Bare UDP Link implements independent, one-way authentication PLPMTUD:

- This section has only two capacity units. `target_len` is the complete logical bare packet
  length after UDP/fake-TCP decapsulation, including `physical_form:u8 |
  destination_receive_id:u32`; ` physical_frame_len` is the complete Physical frame length starting
  from `physical_form` after serialization. In other words, `physical_form` belongs to the
  Physical frame, and only `destination_receive_id:u32` is an extra header of bare UDP relative to
  the Physical frame. The internal PMTU of the bare carrier and `Link::max_datagram_size()` use
  `physical_frame_len`; the business `PhysicalPayload` parameters of `send_physical` still need to
  be calculated according to the Physical encapsulation overhead of the corresponding form and
  cannot be confused with the wire capacity. Link releases `UserIpCapacity` to the LSA, OPEN, and
  path budget after completing the Tinect Forward cost conversion.
- Starts immediately after identity and receiving ID negotiation is completed; the initial
  candidate `target_len` is a conservative 1200 bytes, upper bounded by the conservative logical
  packet capacity corresponding to the address family and fake-TCP outer layer. The successful
  candidate is converted only once: `physical_frame_len = target_len - 4`. Therefore, internal
  `Link::max_datagram_size()` uses `target_len - 4`; external LSA/path capacity must be converted
  to `UserIpCapacity` according to RFC-0037, and subsequent inner MTU calculations must not deduct
  receive ID or Tinect Forward overhead again.
- Probe and ProbeAck use the `0x02` and `0x03` forms of RFC-0015 respectively. The Physical plain
  text of Probe is `probe_id:u64 | target_len:u16 | padding`; the Physical plain text of Ack is
  `probe_id:u64 | target_len:u16`. The exact length of the bare UDP Probe is `1 form + 4
  receive_id + 8 physical_sequence + 10 probe plaintext + padding + 16 physical_tag = 39 +
  padding ` bytes. The sender orders ` padding_len = target_len - 39`; the sender and receiver must
  reject Probes that are less than 39, cannot be represented by `u16`, exceed the current
  detection upper bound, the actual length is not equal to `target_len`, or the padding length
  cannot be accurately derived. The receiver immediately responds with Ack after successful
  verification.
- Use a new random `probe_id` for each candidate and send it up to three times; wait 3 seconds
  after each send. The sender will only accept Acks that match both `probe_id` and `target_len` of
  the current candidate before the end of the third wait, and then invalidate the ID; expired,
  duplicate or unmatched Acks will be discarded. If no matching Ack is found, the upper bound is
  reduced and convergence is searched using binary search. Retest every 600 seconds after
  completion. Continuous large packet transmission errors or continuous over-limit loss trigger
  the black-hole to return to the initial capacity and re-detect after cooling down.
- Probes/ACKs must not enter circuits, topologies, or forwarding queues; forged, duplicate,
  expired, or mismatched ACKs must not change capacity.

`Link::max_datagram_size()` returns Quinn's application DATAGRAM capacity in a full carrier, and
`physical_frame_len` in a bare carrier for this detector. Both are carrier-local Physical frame
upper bounds; LSA `inner_mtu`, path MTU, TUN initial security capacity, and TCP MSS clamp use
Link-scaled `UserIpCapacity` and may not deduct receive ID or Tinect encapsulation again. The 4-byte
header of the receive ID has been deducted when the probe is successful and must not be deducted
repeatedly. If there is a potential bare UDP first hop in the configuration, the corresponding
conservative physical frame lower bound of `1200 - 4` is used when TUN is started.

## Evolutionary boundaries with RFC-0022

RFC-0022 has replaced this section of PMTU Search and Capacity Release state Management: Detector
reuse history `lower_bound`/`upper_bound`, using up hysteresis and a shorter down confirmation
window, and can be canceled when the link is closed or the supervisor exits. It does not replace the
capacity units, Probe/ProbeAck wire format, `target_len - 4` to `physical_frame_len` unique
conversion, authentication, replay protection, solo flight, and probe deadline constraints defined
in this section.

RFC-0014 History In Progress's "Each round starts at 1200, up to three times per candidate, retests
600 seconds after completion" has been replaced by RFC-0022's History Bounds, Consecutive Success
Acknowledgments, and Rapid Decline policy. Any implementation must still guarantee that
`Link::max_datagram_size()` only uses `physical_frame_len` in carrier-local logic and converts it to
RFC-0037's `UserIpCapacity` at Link boundaries; the path budget must not re-deduct bare UDP receive
ID or Tinect Forward overhead.

## Security and Compatibility

The physical frame of bare UDP is still encrypted, authenticated and protected by the replay window
by the Physical AEAD of both adjacent parties, so it only lacks the datagram encryption layer of
QUIC TLS compared to the full carrier. QUIC streams are still protected by QUIC TLS. Receive IDs are
visible in clear text and can be guessed; silent discarding of unknown IDs and Physical AEAD
verification limit their impact and cannot be considered authentication or anti-DoS mechanisms.

Turning off fixed-bit greasing, fixing unique QUIC versions, and rejecting Version Negotiation are
deliberate compatibility constraints that trade QUIC wire behavior for stable offloading. All
connected nodes must be upgraded to this RFC; there is no compatibility layer for older
`quic://`/`quicp://`. Bare UDP shares the underlay socket, source port, and path with the QUIC
stream on the same client endpoint, and therefore inherits the NAT mapping of the active connection;
it does not reuse the inbound-only listener endpoint. External firewall rules that rely on active
traffic to use fixed listener ports must be adjusted to allow temporary source ports. Normal inbound
listener rules will not be affected. Bare UDP does not guarantee the same congestion control or
PMTU status as QUIC. Implementations should provide independent sending pacing or upper limit
(either configuration or heuristic) for the bare UDP data plane to avoid unbounded packet flooding
when competing with QUIC on the same port; the specific algorithm is not specified in this RFC, but
Quinn's CC state machine must not be regarded as the only rate limiter for bare UDP.

The local failure of bare UDP `sendto` must retain errno semantics: `EMSGSIZE` means that the
current underlay cannot carry the Probe, enter the local overlimit branch of PLPMTUD and tighten the
search upper bound; `EAGAIN` or `ENOBUFS` indicates temporary send pressure: enqueue the packet for retry. Neither
error indicates a physical wire failure.
authentication, or protocol error, otherwise the detector will retry quickly on fixed large packets,
exhausting the sending budget and masking the real network status.

After receiving a matching ProbeAck, the PMTU worker must be awakened immediately by the event and
must not unconditionally wait for the complete three-second Probe deadline; the deadline is only
used for black hole determination without Ack. In this way, the bipartite convergence time of a
restricted path is determined by the actual packet loss/overrun situation and will not be fixedly
amplified by each successful detection.

## Testing and Acceptance

1. Configurable unit tests cover four schemes, mixed listener/peer, old scheme rejection, address
   family selection, and fake-TCP platform/setting limitations.
2. The carrier test covers the listener/client endpoint life cycle, active ephemeral port and
   fixed port isolation, QUIC v1 only, forced shutdown greasing, Version Negotiation drop,
   bit-6/form offload, **full scheme** two-way receive ID negotiation (including full),
   concurrent uniqueness, exhaustion, logout, source binding and pre-authentication bare packet
   rejection. The following deny paths must be additionally overridden: Tampering with
   `sender_receive_id` in either Hello or HelloAck causes signature verification to fail; using a
   correctly signed HelloAck with a different `hello_link_nonce` must be denied; Zero receive IDs
   in Hello, HelloAck, or bare UDP headers must be denied; After concurrent dialing convergence
   or Link replacement, bare packets pointing to the old receive ID must not be delivered,
   refresh liveness Or affect the new Link; bare UDP must not be delivered according to the old
   mapping before re-authentication after the source quadruple changes.
3. PLPMTUD tests cover probe/ACK, binary convergence, three failures, periodic retest, black-hole
   fallback, IPv4/IPv6/fake-TCP overhead, and LSA/TUN/MSS capacity propagation. When
   `target_len=1200`, it must be asserted that the bare wire is 1200 bytes, the Physical
   frame/Link/LSA capacity is 1196 bytes, and the TUN path will not repeatedly deduct 4 bytes of
   the receive ID.
4. Run four carrier two-node tests and mixed scheme dial-up tests on Linux CI, and verify the
   detection and data forwarding of `quic://` and `quic-faketcp://` under restricted MTU; after
   testing, confirm that namespace, TUN, routing, RST guard, and raw socket resources are all
   cleared. It is also necessary to fix the client listener port in the stateful SNAT topology,
   confirm that the active connection source port seen on the server side is a non-zero temporary
   port and not equal to the listener port, and verify the two-way Link and TUN ping for the four
   carriers.

## Open Questions

- None yet. Implementations must first follow the Physical frame definition of RFC-0015 before
  accessing the bare UDP directional header and PMTU detection of this RFC.

## Implementation Notes

The implementation has covered four endpoint schemes, listener/peer carrier decoupling, listener
inbound fixed port and active dial-up independent temporary client endpoint each time, QUIC v1 and
fixed-bit constraints, fixed-width Hello/HelloAck, receive-id route logout, UDP/fake-TCP hybrid
offload, bare Physical transceiver and independent Probe/ProbeAck PMTU search. Linux fake-TCP with
restricted MTU scenarios covered by network integration CI. The shutdown notification of the hybrid
UDP reader uses a single reader permit that can be retained to avoid the failed active endpoint from
losing the shutdown notification and leaking the temporary socket when the reader task has not
polled for the first time; the corresponding immediate drop/rebinding regression test has been added
to the underlay test.
