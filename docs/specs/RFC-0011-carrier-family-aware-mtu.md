# RFC-0011: Carrier and address family aware MTU caps

> RFC-0037 adds two QUIC units that are not distinguished by this RFC: the following table is the
  path-payload upper bound of DPLPMTUD; the application DATAGRAM upper bound of full QUIC also
  deducts Quinn's packet/DATAGRAM framing (currently conservative value 38 bytes), and then Link
  is converted to `UserIpCapacity`.

- Number: RFC-0011
- Title: Carrier and address family aware MTU upper limit
- Status: Implemented
- Created: 2026-07-25
- Last updated: 2026-08-15

## Background and Problem

QUIC over UDP uses different outer headers than QUICP. In order to ensure that QUICP IPv6 packets do
not exceed 1500 MTU, the old implementation sets the upper limit of DPLPMTUD for all connections to
1440 bytes. This will use 12 bytes less for a normal QUIC IPv6 connection, 32 bytes less for an IPv4
connection, and 20 bytes less for IPv4 QUICP.

## Goals and Non-goals

The goal is to set the correct DPLPMTUD cap based on the actual carrier and the actual resolved
address family, and have the listening and egress sides use a consistent configuration. Non-goals
are guessing the domain's address family, bypassing PMTUD, or extending the 1500 MTU assumption to
unknown jumbo-frame/tunnel paths.

## design

Use the following caps on standard 1500 byte paths:

| carrier | IPv4 | IPv6 |
| --- | ---: | ---: |
| QUIC/UDP | 1472 | 1452 |
| QUICP/fake-TCP | 1448 | 1428 |

The upper limit is the outer IP MTU minus the IP and UDP/TCP headers, which is still not the final
number of available bytes of application layer DATAGRAM; QUIC packet header, DATAGRAM frame header
and AEAD tag will also take up space.

The address family selection rules are as follows:

1. The listening end creates a server transport config based on the address family bound to
   `SocketAddr`.
2. The outbound end first resolves the peer endpoint; the domain name must first be resolved to
   `SocketAddr`, and then use `remote.is_ipv4()` to select client transport config.
3. When the same domain name is resolved to IPv4 or IPv6, the corresponding upper limit is used
   respectively; the address family cannot be inferred from whether the string contains colons,
   configuration URLs, or peer names.
4. If DNS returns multiple addresses, the connection supervisor uses the address family resulting
   from that resolution for each actual attempt. The last parsed result must not be cached as a
   permanent address family conclusion.
5. When the actual path MTU is lower than the standard value, DPLPMTUD is still responsible for
   converging the configured upper limit downward; the configured upper limit only searches for
   the upper bound.

## Compatibility and security

The on the wire packet format remains unchanged. New nodes can still establish connections with old
nodes; old nodes may continue to use the 1440 cap, so the actual effective MTU of the connection is
limited by a combination of peer QUIC transport parameters and path detection. Increasing the search
limit does not turn off authentication, encryption, or ACLs, nor does it allow large packets without
PMTUD authentication to be injected directly into TUN.

## Implementation Notes

- `src/mtu.rs` defines the upper limit and pure function selection logic for four carrier/address
  family combinations.
- `src/carrier/mod.rs` is configured according to the listening address family on the server side,
  and is configured according to the resolved remote `SocketAddr` on the client side.
- `src/main.rs` Passes the current node carrier protocol into the outbound connection
  establishment process.

## Testing and Acceptance

- The unit test covers four combinations of numerical selections.
- `cargo fmt --check`, Strict Clippy, `cargo test` must pass.
- IPv4/IPv6, QUIC/QUICP real links verify the handshake and large datagram respectively; capture
  packets to confirm that the length of the outer packet does not exceed the underlay MTU.
- When using the domain name endpoint, the environment verification selection results of A and
  AAAA are returned in DNS respectively; you cannot only test the literal IP.
- Verifying DPLPMTUD downward convergence on paths below 1500 does not treat the fixed
  1472/1452/1448/1428 (or 1434/1414/1410/1390 for application DATAGRAM) as the actual available
  value.

## Troubleshooting points

If QUIC still shows the old 1440 upper limit, first make sure you are running the new binary and
check the `SocketAddr` address family that the endpoint actually resolves. The path-payload of
ordinary QUIC IPv6 should allow detection of 1452 (application DATAGRAM is 1414), QUICP IPv6 should
allow detection of 1428 (application DATAGRAM is 1390), and the corresponding value of ordinary QUIC
IPv4 is 1472/1434. If large packets still fail, troubleshoot according to the outer packet length of
RFC-0010, `EMSGSIZE`, packet capture, nftables and path MTU processes instead of continuing to
increase the upper limit.
