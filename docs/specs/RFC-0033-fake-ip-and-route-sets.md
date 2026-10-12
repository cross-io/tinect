# RFC-0033: FakeIP and file routing sets

- Status: Implemented
- Created: 2026-08-13
- Last updated: 2026-08-13

## Background and Problem

Tinect's original routing can only configure CIDR item by item, and cannot efficiently reuse large
domain names or IP lists. Domain name offload also needs to retain the domain name decision during
DNS query in the L3 TUN data plane, and at the same time, the relay, remote Tinect or public network
target cannot be aware of FakeIP.

## Goals and Non-goals

The goal is to provide optional local UDP/TCP FakeIP DNS, source address translation and unified
SiteSet files. SiteSets can mix domain names and IP-CIDR; CIDR-only SiteSets do not rely on FakeIP.
The specific selector and matching index are defined by RFC-0035.

The first release does not offer hot reloading, DoH/DoT, DNSSEC signing, map persistence across
reboots, or application layer ALG. In order to allow overlapping source addresses to be returned
unambiguously, the Circuit data plane adds a reverse direction, which is an incompatible on the wire
behavior change.

## Terminology

- FakeIP: A synthetic destination address returned to the local DNS client for use in restoring
  domain name routing decisions.
- return flow: The bounded state of the final exit recorded in reverse five-tuple, including the
  original transmission identifier and source Circuit.
- SiteSet: Immutable domain name/CIDR hybrid route selector referenced by `SetId`, see RFC-0035
  for specific format and index.

## design

### Configure and load

See RFC-0035 for the selector and SiteSet file syntax and index of `peers.*.routes[]`, paths
`override_routes[]` and `direct.routes[]`. Relative file paths are resolved based on the main
configuration directory and are strictly loaded at startup; any illegal execution fails to start.

The loader first deduplicates I/O according to the canonical path, and then deduplicates the
immutable collection according to the canonical content SHA-256. Peer route, direct route, override
and snapshot only save `SetId` and priority. The IP-CIDR in the SiteSet participates in the
selection of the longest prefix in the routing index; the domain name query will match each distinct
set at most once, and merge all hit candidates, and the same node will take the highest priority.

### DNS and caching

FakeIP listener binds UDP/TCP to the same address at the same time. The global upstream must be
explicitly configured as an IP literal, attempted in sequence, using TCP after UDP truncation,
without fallback to the system resolver. `peers.<exit>.upstream_dns` overwrites the global value,
and `override_upstream_dns` of the active manual path overrides the peer value; explicit override
must be non-null, and the effective value is fixed as Circuit lease metadata and replaced atomically
with path migration. Native direct always uses the global value. Missing domain names are forwarded
unchanged on this machine. When the SiteSet domain name rule is hit, all peer candidates and
`direct.routes` local candidates are summarized. The same node takes the highest priority, and tries
one by one from high to low by priority; when the priority is the same, the peer precedes the local
candidate. The peer candidate must have a healthy circuit, and each egress tries the valid upstream
of the lease in turn; the local candidate directly accesses the global upstream. The query payload
and response are end-to-end encrypted using independent direction keys, and the final egress is
connected to the upstream. SERVFAIL or transfer failure continues to next upstream/candidate,
NXDOMAIN and NODATA are valid DNS results.

The remote DNS upstream address must pass `allowed_routes` corresponding to the source node; it is a
Circuit internal service and is not affected by `allowed_local_ports` which only describes the local
TUN delivery surface. Native DNS queries do not enforce egress ACLs. After all explicit candidates
fail, only `direct.fallback: true` appends a native final attempt. The successfully parsed peer or
direct exit is saved with the DNS cache/FakeIP mapping, and subsequent data will use this exit
first; if the successful peer is no longer healthy, re-select according to priority from all
currently hit peer and direct candidates, and the invalid sticky binding will not be used.

All forwarding record TTLs are clamped to the configured upper and lower bounds. The FakeIP is
renewed when used by DNS queries or associated data traffic; the activity stream pins the
corresponding FakeIP. Return SERVFAIL when the pool is full and has no expired items. When IPv6 is
disabled, AAAA, HTTPS and SVCB return NODATA; HTTPS/SVCB/ANY that hits the domain name also returns
NODATA to prevent address hint from bypassing the domain name policy.

### Routing and address translation

Routing selection is completed before the target is rewritten: after FakeIP restores the domain name
and resolution exit, the available resolution exit takes priority; when the successful peer is
unhealthy, all healthy peers that hit the SiteSet domain name rules compete with explicit direct
candidates again according to priority. Ordinary IP route first takes the longest prefix among all
matching items of peer/direct, and then compares the effective priority within the prefix. direct
will win only if the priority is strictly higher than peer, and the same priority will be reserved
for peer; when the same exit appears through multiple hit rules, the highest priority will be used.
When there is no healthy peer, the existing Circuit ensure is still requested; only
`direct.fallback: true` is allowed to append the local final exit when there is no explicit direct
candidate, otherwise the packet will be strictly discarded. The local export first completes the
FakeIP address/identity conversion at the source, and then re-injects the real target packet into
TUN; when the return packet enters from TUN, it directly checks the source flow and restores it,
without going through the remote return flow.

The security circuit source changes the IP header from `Original Source → FakeIP` to `Node side TUN
source address → real destination `; the local direct source is temporarily changed to ` FakeIP → real
target`. FakeIP only serves as the return anchor point of the source node POSTROUTING NAT. The
masquerade occurs before leaving the source node, so the remote end will not see FakeIP. Both paths
save the original source and FakeIP in the local flow table. Only the FakeIP forward packet of the
security circuit adds the `[tag, address-length, fake-address]` envelope in the end-to-end encrypted
payload; the ordinary Forward still directly carries the original IP packet. The relay does not
decrypt or interpret the envelope. The final exit decrypts and strips off the FakeIP
meta-information, and based on this only creates a return flow for the FakeIP packet. TCP/UDP uses
the source port, and ICMP/ICMPv6 Echo uses the Identifier; when a reverse key conflict occurs within
the same source node, the replacement value is first allocated from the corresponding 16-bit space.
After successful authorization, the final exit establishes a second-layer return flow based on the
source Circuit, and assigns the identifier again when different Circuits conflict. The rewrite fixes
TCP, UDP, ICMP and ICMPv6 checksums simultaneously. Unknown protocols are associated by node-side
source address, real destination, protocol and circuit on a best-effort basis; fail closed when
ambiguity occurs. AH and non-first releases that cannot be safely associated are explicitly
rejected; first release dependency paths MTU/MSS clamp avoids inner fragmentation.

The return flow saves the source Link instance, Circuit label, node-side source address, optional
FakeIP meta information, and lease period. The public network return packet is naturally `Real
destination → Node side TUN source address`; after it enters the daemon from the egress TUN, it
matches the table before the ordinary routing query, restores the egress layer identifier, and
carries back the FakeIP metainformation in the encrypted reverse payload and returns along the
original Circuit. relay only forwards the ciphertext according to the reverse binding of the
existing label. After source verification and decryption, check the local wire flow, verify the
optional FakeIP meta information, restore the source layer identification, and change the address to
`FakeIP → original source`. The FakeIP address is no longer located in the common IP header across
nodes; the envelope only carries the FakeIP meta-information required for source recovery, and does
not carry domain names, real addresses or node identities, nor does it participate in path
selection. The forward and reverse keys are derived from the Circuit data key using different
contexts, and the sequence number spaces are not reused with each other.

The address no longer determines the backhaul peer, so multiple nodes can use overlapping origin
addresses without the need for alias pools or per-node unique FakeIP address configuration. The
egress operating system only needs to send the TUN node address of the source node back to the
corresponding circuit; FakeIP pool should not be installed on the egress or relay, nor can it be
used as a basis for node/path selection. When the source address route on the node side is missing,
the return packet will not enter the daemon, and the deployment error will fail closed.

## Security and Compatibility

Reverse frames and DNS service frames are still end-to-end encrypted data. The relay can only see
the existing circuit label, direction category, sequence number and length, but cannot see the
domain name, upstream address or DNS response. The final exit continues to verify the real
destination through `EgressPolicy::authorize()` before establishing a return flow; rejected packets
must not create a state. Remote DNS alone and only through `allowed_routes` authorization. The
source node's FakeIP pool and the explicit IP prefix of the peer/direct are installed to the native
TUN when managed by `managed_routes`; egress and relay only install the required backhaul routes for
the node-side TUN address. System routing I/O is not performed at `managed_routes: false`. Linux
`nft_healthy_set` treats an explicit direct IP route as always available; when matching a direct
domain route, the FakeIP pool still only serves as a capture prefix local to the source node.

FakeIP does not construct runtime, DNS listener/worker, cache, map, domain upstream snapshot or
FakeIP flow state when not configured. TUN transceiver tasks are assigned to static disabled
implementations at startup. Ordinary source packet hot paths do not execute the
`Option<FakeIpRuntime>` branch, do not add envelopes, and do not enter the exit return-flow; general
Circuit and ordinary `SecureRoute` do not carry the FakeIP upstream field. The peer/path override is
only resolved in snapshot builds where domain route exists, and the effective list of the same exit
is shared with `Arc`. To allow a node that does not have native FakeIP enabled to act as an egress
for other nodes, the TUN recycling path retains a return-flow active bit that is initially false;
the absence of an established FakeIP flow produces only a predictable atomic read, without parsing
the packet or accessing the hash table.

The return flow has a capacity limit and an idle lease. Packets will be strictly lost when capacity
is exhausted, unknown return packets, transmission identification space is exhausted, Circuit/Link
has been revoked or reverse authentication failure. Link replacement and Circuit closure must clear
the associated state, and old return packets must not be delivered to the new Circuit. The
port/Identifier assigned by the egress remains unambiguous when different nodes concurrently use the
same address, port, and destination.

The configuration format has new fields, but does not need to be compatible with older versions.
State management responses are updated from prefix-only to selector, entry count, and candidate
list; large sets are not expanded. Dynamic domain names do not enter the Prometheus tag.

## Testing and Acceptance

- Strict parsing, relative paths, canonical path/content hash deduplication and route/override
  sharing.
- CIDR longest prefix, merging of all domain name hit candidates, peer/direct fair ranking, same
  priority peer priority, healthy switching and no candidate fail closed.
- UDP/TCP DNS, upstream truncation, TTL, IPv6/HTTPS/SVCB, pool exhaustion and failure responses;
  global /peer/path upstream override priority and lease pinning; healthy peer and explicit direct
  resolution by priority, remote route ACL, `direct.fallback` final attempt, and successful egress
  stickiness/failure reselection.
- IPv4/IPv6 bidirectional address rewriting, TCP/UDP ports, ICMP/ICMPv6 Echo Identifier,
  checksums, non-first slice/AH reject, unknown protocol and conflicting assignments.
- Privileged end-to-end coverage for direct connections, multiple hops, duplicate sets,
  overlapping source addresses and identical quintuples, link substitution, reverse frame
  duplication/lateness, and missing backhaul capture routes.

## Implementation Notes

Implementation is located at `route_sets`, `fake_ip`, `return_path`, split `config`, routing
snapshots, and daemon lifecycle boundaries. The configuration supports global/peer/path three-level
DNS upstream coverage, and the FakeIP-disabled data plane uses static specialized paths. Acceptance
passed 208 library tests, 26 binary tests, as well as direct connection, multi-hop/Link replacement,
path/peer DNS coverage, explicit direct route, final fallback and fallback capture missing
fail-closed scenarios under the Linux namespace; the corresponding scenarios have been added to the
GitHub Actions matrix.
