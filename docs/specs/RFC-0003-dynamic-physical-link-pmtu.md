# RFC-0003: dynamic physical-link-pmtu

- Status: Implemented
- Created: 2026-07-22
- Last updated: 2026-08-15

> Note (2026-08-15): This RFC still defines local PMTU/DPLPMTUD detection, but the capacity unit
  published to the topology has been replaced by
  [RFC-0037](RFC-0037-user-ip-capacity-and-tun-mtu-semantics.md); the detector retains the
  Physical frame unit internally, and Link publishes `UserIpCapacity` to the outside world.

## Background and Problem

The static `peers.*.pmtu` does not reflect the actual underlay path and also incorrectly requires
the source node to configure a local PMTU for the far relay edge. MTU changes along the path can
cause TUN injection of very large packets, and ICMP Packet Too Big is unreliable in NAT or firewall
environments.

## Goals and Non-goals

The goal is to detect only physical QUIC adjacencies, safely propagate each node's measured
unidirectional capacity into multi-hop path calculations, and tighten TCP SYN MSS by default.
Non-goals are circuit-level detection, end-to-end detection, letting relays check or modify
end-to-end payloads, or rolling compatibility with old protocol nodes.

## design

Each QUIC Link uses Quinn's DPLPMTUD. Both sides start from a QUIC-safe 1200-byte path-payload
starting point, and the search upper bound is determined by the actual carrier and address family;
each direction is measured independently. Quinn's `MtuDiscoveryConfig` uses path-payload units,
while `Connection::max_datagram_size()` returns application payload units minus QUIC 1-RTT/DATAGRAM
framing. Link then deducts the Tinect Physical Forward and DATA overhead, and regularly publishes
`inner_mtu` in the LSA `neighbors` item signed by this node, whose unit is the complete user IP
byte.

When the source node calculates the path MTU, the first hop uses the real-time `UserIpCapacity` of
the local link, and subsequent edges read the `inner_mtu` of the corresponding LSA. Path calculation
no longer repeatedly deducts any carrier, receive ID, or Tinect encapsulation overhead. Remote LSAs
that are missing, expired, or have not yet been received use a conservative initial capacity. TUN
uses the same conservative value at startup and synchronizes the configured upper limit with the
active import path minimum during route recalculation.

`peers.*.pmtu` was deleted. `tun.clamp_mss` defaults to `true`; when enabled, only the existing MSS
option will be rewritten by valid path MTU on the outbound TCP SYN of the selected overlay path, and
when turned off, no packets will be rewritten. The existing rejection behavior for over-MTU packets
remains unchanged.

## Agreement, Security and Compatibility

`LinkMetric.inner_mtu` incorporates LSA signature bytes, and the Link-State signature domain and
coverage protocol versions are upgraded. Tampering capacity, replay advertisements and expired
advertisements must be rejected based on existing LSA verification; the relay only reads the LSA and
does not touch the end-to-end inner IP payload. The old and new nodes are incompatible, and the
interconnected nodes must be upgraded as a whole. `pmtu` in the old configuration is rejected due to
strict configuration parsing, and the operator must delete this field and restart.

## Testing and Acceptance

Unit tests cover LSA capacity field directionality, expiration fallback and signature tamper
rejection, encapsulation overhead calculations, initial conservative TUN MTU, `clamp_mss` default
and shutdown behavior, and IPv4/IPv6 TCP SYN MSS clamp. Implemented through `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`. Real network acceptance
uses a three-node environment to verify multi-hop forwarding under different physical Link MTUs, TUN
synchronization after capacity changes, and cleanup of all network resources.
