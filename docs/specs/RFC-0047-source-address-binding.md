# RFC-0047: Conditional source address binding

- Number: RFC-0047
- Title: Conditional source address binding
- Status: Implemented
- Created: 2026-09-01
- Last updated: 2026-09-01

## Background and Problem

Tinect's end-to-end data frame can authenticate the identity of the sending node, but the inner IP
source address is provided by the sending node, and its ownership cannot be inferred based on the IP
address alone. If node B is configured with a default route and node C owns an intranet `/32`, B may
still construct a data packet whose source address belongs to C.

The goal is not to configure a complete source address whitelist for each peer, but to protect
explicitly claimed intranet addresses while maintaining existing reachability of unclaimed addresses
(such as Internet response addresses).

## Goals and Non-goals

Target:

1. Establishes one or more sets of allowed peer identities for an explicitly bound IP/CIDR.
2. Source addresses that miss any bound CIDR do not add additional restrictions.
3. Explicit `bind_addresses` and `routes[].bind` abbreviations for peers are also supported.
4. Maintain end-to-end opacity of relay nodes and do not introduce new wire fields.

Non-goals:

- Does not change destination routing, priority, path selection, or egress NAT semantics.
- Do not force all unbound public network addresses to belong to a certain peer.
- Does not use or replace system conntrack; existing status management of the return path remains
  unchanged.

## the term

- **Bind CIDR**: IP network from `bind_addresses` or `peers.<name>.routes[].bind: true`.
- **Binding owner**: Declare the end-to-end public key identity of the peer that binds the CIDR.
- **Source identity**: The public key carried by the authenticated session in the security
  circuit; in the old single link mode, it is the peer identity of the authenticated Link.

## Configuration design

Peer can be declared manually:

```yaml
peers:
  client:
    bind_addresses:
      - 10.0.0.1/32
```

You can also let IP routes generate bindings at the same time:

```yaml
peers:
  client:
    routes:
      - ip_cidr: 10.0.0.1/32
        priority: 100
        bind: true
```

`bind` defaults to `false`. It is only allowed to appear on the `ip_cidr` route of
`peers.<name>.routes[]`; domain, site set, direct route and path override do not generate bindings.
`bind` does not affect the priority or selection results of route candidates.

The two types of sources for each peer are merged when the configuration is loaded. The owners of
the same CIDR are unioned; overlapping CIDRs are also unioned by the bindings of all hits. Using
`bind: true` against `0.0.0.0/0` or `::/0` binds the entire address family, a behavior the
configuration documentation explicitly warns about.

## data plane behavior

The final decryption node obtains the authentication source identity from the data frame and obtains
the source address from the inner IPv4/IPv6 header. Compute the bound CIDR of all hits for each
packet:

- No hit: Allow the authentication source identity to continue processing;
- Hit and source identity belongs to either owner: allowed;
- Hit but source identity does not belong to owner: discard and log `source_binding:denied`;
- Unable to resolve IP source address: discard and log `source_binding:unsupported_or_malformed`.

Verification occurs after final decryption, Circuit binding refresh, return state creation and TUN
delivery, and is independent of `EgressPolicy::authorize()`. Therefore, when no egress ACL is
configured, the binding still takes effect. Both `Forward` and authenticated `Return` data use the
same set of source binding rules; the DNS service payload is not an inner IP packet, and this rule
is not executed.

Relay only forwards opaque frames based on the local circuit label, does not read the inner source
address, and does not perform source binding checks. The old single link mode does not have an
end-to-end source public key, so the authentication physical Link's `peer_identity` is used as the
source identity to perform the same IP/CIDR determination.

FakeIP continues to use its existing inner address translation. The source binding matches the IP
source address seen by the receiverdata plane after translation, without modifying the FakeIP
envelope or other data frame formats.

## Security and Compatibility impact

This function does not change the behavior of unbound addresses by default; only after binding CIDR
is configured, the relevant addresses will be restricted by peer identity. It prevents the
authenticated peer from using the declared intranet source address, but does not prevent the
authenticated peer from using any undeclared public network source address. Existing configurations
can gradually add bindings to intranet addresses without the need for a wire compatibility layer.

Source binding is not a replacement for circuit admission: unestablished or unauthorized secure
circuits must still be rejected. Physical Link authentication and the trust boundary of the old
single link remain unchanged.

## Migration and deployment

Existing configurations do not need to be modified, and all binding fields are turned off by
default. It is recommended to add `bind: true` to the clear intranet address at the final decryption
node, or use `bind_addresses` to express the ownership of addresses that do not participate in
destination routing; undeclared addresses such as Internet responses will continue to be processed
according to the original path. If the node has the global default route enabled, keep the route's
`bind` as `false`, and only add narrower bindings for the addresses actually held by the peer.
Configuration updates take effect according to the existing configuration load/restart process,
without the need to coordinate relay nodes, change the data frame format, or upgrade the wire
compatibility layer.

## Testing and Acceptance

- Configuration resolution overrides explicit `bind_addresses`, route `bind` default value,
  illegal non-`ip_cidr` selector, multiple peers bound to the same CIDR and overlapping CIDRs.
- The data plane covers legal/fake sources of bound addresses, unbound `1.1.1.1`, IPv4/IPv6,
  unknown protocols, fragmentation, Forward/Return, FakeIP, old single links and multi-hop relays.
- The fake source must not refresh the binding, create a backhaul status, or write to the TUN when
  it is dropped.
- Complete `cargo fmt --check`, Clippy, `cargo test` and related privileged network tests.

## Implementation Notes

The implementation has been completed: the configuration is loaded to generate a conditional source
address binding set, and both the secure data plane and the old single-link entrance are checked
before delivery; unbound addresses maintain compatible semantics that do not limit the source peer.
Rust unit tests, formatting, and Clippy passed.
