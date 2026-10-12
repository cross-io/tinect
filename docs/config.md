# Configuration reference

Tinect uses YAML configuration and rejects unknown fields. Node names are local labels; network
identities are derived from Ed25519 public keys. `listen` and `peers.*.endpoints` support
`quic://HOST:PORT`, `quicfull://HOST:PORT`, and, on Linux,
`quic-faketcp://HOST:PORT` and `quicfull-faketcp://HOST:PORT`. Enclose IPv6 addresses in square
brackets. The listener and peer endpoints can use different carriers. The legacy `quicp://` scheme
is rejected. Bare UDP still uses a separate Physical data plane. Nodes that only initiate
connections can omit `listen`; the carrier infers the temporary local address from the endpoint in
`connect_to`.

`quic://` and `quic-faketcp://` use a separate bare Physical data plane and receive-ID semantics.
`quic-faketcp://` and `quicfull-faketcp://` support IPv4 and IPv6 on Linux and require raw-socket
access plus `CAP_NET_RAW` and `CAP_NET_ADMIN`. The fake-TCP carrier supports Linux `fwmark`, but
not `carrier_interface`.

Below is a configuration skeleton covering all fields. Just delete unnecessary optional segments by
role.

```yaml
# Required: Locally readable node name; must not contain / or NUL.
id: laptop

# Optional; defaults are true / false. These control inbound Links from configured peers and relaying for known sources, respectively.
accept_connections: true
allow_transit: false

# Identity key source priority: IDENTITY_KEY environment variable, identity_key, then identity_key_path.
# Provide at least one source. When set, the environment variable takes precedence over configuration.
identity_key_path: ./node.key
# identity_key: BASE64_ED25519_SECRET

# Required: The local QUIC carrier listening address. fake-TCP uses quic-faketcp:// or quicfull-faketcp://.
listen: "quic://[::]:4433"

# Optional: Resolve the DNS upstream of hostname in peers.*.endpoints.
# Each item must be an IP literal; the port can be omitted, and the default is 53. Try them in order and fall back to system DNS if all fail.
# Use the system resolver directly when not configured. listen must still be a literal IP:PORT.
dns_servers: ["10.0.0.53", "[2001:db8::53]:5353"]

# Optional: enable source-side FakeIP DNS and address translation when this section is present.
fake_ip:
  listen: 127.0.0.1:53
  upstream_dns: [1.1.1.1, 8.8.8.8]
  disable_ipv6: false
  ipv4_pool: 198.18.0.0/15
  ipv6_pool: 'fd74:696e:6563:7400::/64'
  min_cache_ttl_secs: 60
  max_cache_ttl_secs: 86400
  max_entries: 131072

# Optional, only effective for quic-faketcp:// / quicfull-faketcp://.
# When omitted, use the publicly known compatibility default "ihciah/tinect" for RST protection.
# This default does not protect against active injection. Configure the same private string at both ends in production.
# Set to false to disable the fake-TCP RST guard (RST packets will not be filtered).
fake_tcp_reset_key: "replace-with-a-shared-secret"
# fake_tcp_reset_key: false

# Optional, Linux-specific: Set SO_MARK for QUIC UDP or fake-TCP raw-IP bearers.
fwmark: 66
# Optional, macOS only: Bind the quic UDP carrier socket to the specified interface (quicp does not support it).
carrier_interface: en0
# Optional, default true: whether to install/clean system routes exported by peers.*.routes.
managed_routes: true
# Optional, Linux-specific: Maintain an nft set of currently healthy Tinect candidates.
# Created by Tinect if table/set does not exist; does not manage nft rules, marks or routes.
nft_healthy_set:
  prefix: router_policy:tinect_healthy
# It can also be specified explicitly by address family, and the explicit value overrides the prefix derived value.
  # v4: router_policy:tinect_route_v4
  # v6: router_policy:tinect_route_v6
# Optional, default false: whether to destroy the set/table in the configuration when exiting.
  destroy_set: false
  destroy_table: false

# Optional, Linux-specific: use native direct as an explicit routing candidate and/or final fallback.
# DSCP only has 6 bits; this field is also a loopback detection marker.
direct:
# Default false; final native egress is only enabled if all matching peer routes are unavailable.
  fallback: true
  dscp: 46
# Required, non-zero u16; this conntrack zone must be exclusive to this Tinect instance.
  conntrack_zone: 32123
# Optional, non-zero complete 32-bit packet mark (can be written in hexadecimal). This value is exclusive to this function.
# After configuration, Tinect creates the prerouting mangle chain through libnftnl/libmnl,
# Set mark, clear DSCP, and discard loopback packets with this mark that enter TUN again.
  fwmark: 0x100
# Optional: Use the same selector and priority as peer routes to allow local exports to participate fairly.
  routes:
    - site_set: ./rules/direct-domains.txt
      priority: 120
    - site_set: ./rules/direct-cidrs.txt
      priority: 80
# When managed_routes is turned on (default), Tinect will also automatically install POSTROUTING masquerade.
# The back-injection packet leaves the machine with the egress interface address; the administrator's advanced SNAT/masquerade rules have higher priority.

# Optional: Trusted shell commands to be executed sequentially after the network configuration is completed and before the network configuration is recycled.
# Each command is executed independently with /bin/sh -ec, and TINECT_TUN is set as the interface name; a failure will not prevent subsequent commands.
# Must use list form, even if there is only one command.
post_up:
  - 'logger -t tinect "${TINECT_TUN} is ready"'
pre_down:
  - 'logger -t tinect "${TINECT_TUN} is stopping"'

tun:
# Optional, default true. false means pure relaying, without creating a TUN or modifying the local network.
  enabled: true
# When enabled is true: the name can be omitted (empty string by default), but should usually be specified explicitly.
# macOS uses system interface names such as utun0 and utun1.
  name: tinect0
# Required when enabled is true, at least one CIDR address.
  addresses: [192.168.233.10/32, 'fd00:233::10/128']
# Optional, default is 1280; when enabled is true, it must be 576..=9000.
# Indicates the maximum length of a complete user IPv4/IPv6 packet, excluding Tinect DATA and Physical
# Forward, receive-id or QUIC/fake-TCP outer overhead.
  mtu: 1280
# Optional, default true: Tighten the MSS of outbound TCP SYN according to the current overlay path MTU.
# The clamp uses the real-time path budget, not a snapshot; FakeIP routes account for their envelope.
# TCP packets above the budget are segmented in user space. Oversized non-TCP packets are dropped
# and trigger rate-limited ICMP Fragmentation Needed / Packet Too Big errors (RFC-0049), preventing
# silent black holes even when GSO is enabled.
  clamp_mss: true

runtime:
# Optional; by default, /run/tinect/<id>.sock is used by platform (macOS: /var/run/tinect/<id>.sock).
  status_socket: /run/tinect/laptop.sock
# Optional; only loopback HTTP addresses are allowed.
  metrics_listen: 127.0.0.1:9900
# Optional, default 0: number of decrypted inner IP packets retained; 0 means off.
  pcap_buffer_packets: 1024
# Optional, default 10, range 1..=60.
  shutdown_timeout_secs: 10

link_health:
# The following are optional; default is 10 / 35 / 2 (seconds).
  keepalive_secs: 10
  idle_timeout_secs: 35
  reconnect_interval_secs: 2

path_migration:
# The time the preferred path must be continuously ready; default is 1 second.
  readiness_stability_secs: 1
# The deadline to complete migration after the preferred path is ready; default is 5 seconds.
  deadline_secs: 5
# The draining window of the old circuit after the new circuit is successful; default is 1 second.
  drain_timeout_secs: 1

peers:
  relay:
# Required: peer’s Base64 Ed25519 public key.
    public_key: REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY
# Required: address list; can be empty, but there must be at least one address when referencing it in connect_to.
    endpoints: ["quic://relay.example:4433"]
# fake TCP example:
    # endpoints: ["quic-faketcp://[2001:db8::10]:4433"]
# Optional; if omitted, inherit the top-level accept_connections and allow_transit values.
    accept_connections: true
    allow_transit: true
# Optional, default false: allow this peer to carry traffic with unknown source/destination.
    allow_relay: false
# Optional: bind these inner source addresses to this peer. If a source address matches a binding,
# only the bound peer identity may use it; addresses with no matching binding are unrestricted.
    bind_addresses: [10.64.0.2/32]
  exit:
    public_key: REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY
    endpoints: []
# Optional: Override fake_ip.upstream_dns when this node serves as a FakeIP DNS egress.
    upstream_dns: [9.9.9.9, 149.112.112.112]
# Optional: The prefix and egress priority imported to the Tinect route selector; priority defaults to 100.
    routes:
      - ip_cidr: 0.0.0.0/0
        priority: 100
      - site_set: ./rules/proxy-domains.txt
        priority: 120
      - site_set: ./rules/proxy-cidrs.txt
        priority: 80
    paths:
      - path: [laptop, relay, exit]
# Only takes effect when this path becomes the currently active path; does not enter the wire path.
# This item overrides exit.upstream_dns; if omitted, the node or global value will continue to be inherited.
        override_upstream_dns: [1.1.1.1, 1.0.0.1]
        override_routes:
          - {ip_cidr: 0.0.0.0/0, priority: 0}
          - {ip_cidr: 192.0.2.0/24, priority: 80}
      - path: [laptop, exit]
# Not writing selector means overwriting all routes declared by exit.
# priority_delta can be negative; adjusted <= 0 to disable candidates.
        override_routes:
          - {priority_delta: -20}

# Optional: The peer name for active dialing. Each entry must be a unique, configured peer with non-null endpoints.
connect_to: [relay]

# Optional: The maximum repair datagrams/source datagram allowed by the passive receiver.
# 0 means off; non-zero value is at least 0.001; range is 0..=8.
repair_rate: 0

# Use object writing when FEC needs to be enabled for an active connection; string writing remains repair_rate=0.
# connect_to:
#   - peer: relay
#     repair_rate: 0.75

# Optional: Targets without manual paths use automatic topology search; each constrains the target's automatic path.
path_policies:
  exit:
    prefer_via: [relay]
    require_via: [gateway]
    avoid: [untrusted-relay]
    max_hops: 4

# Optional: Rules that allow forwarding to destinations other than the local TUN address when this node serves as an egress.
allowed_routes:
  - allow: [0.0.0.0/0, '::/0']
    deny: [10.0.0.0/8, 'fc00::/7']
    for: [laptop]

# Optional: local delivery ACL of the TUN address of this node.
allowed_local_ports:
  - allow: [tcp(443), udp(53), icmp, icmpv6]
    deny: [tcp(25)]
    for: any_known

```

## Nodes, TUN and runtime

The node identity private key can be provided through the `IDENTITY_KEY` environment variable,
`identity_key`, or `identity_key_path`. The priority is environment variable, inline configuration,
and file path. `IDENTITY_KEY` should be a Base64-no-pad encoded 32-byte Ed25519 private key; the
environment variable, when present, overrides the identity source in the configuration.
Configuration loading fails when none of the three are provided; simultaneous configuration of
`identity_key` and `identity_key_path` will still be rejected. `tinect keygen --output node.key` can
be used to generate a private key; `tinect pubkey --key node.key` output can be filled in with the
public key of `peers.*.public_key`.

`fake_tcp_reset_key` controls the fake-TCP RST guard. When omitted, Tinect uses the publicly known
compatibility default `ihciah/tinect`; this supports interoperability but does not protect against
active injection. For protection, both ends must configure the same non-empty private string.
Setting the field to `false` disables the RST guard, so fake-TCP RST packets are ignored and the
remote session is cleaned up only after the QUIC/fake-TCP idle timeout.

`tun.enabled` defaults to `true`. At least one `tun.addresses` must be configured when enabled,
`mtu` ranges from `576..=9000`. `name`, `addresses` and `mtu` can all be omitted when disabled. Pure
relays should use:

```yaml
tun: {enabled: false}
```

When `tun.enabled` is `false`, Tinect creates no TUN, routes, or firewall resources and does not run `post_up` or `pre_down`. Do not configure `post_up`, `pre_down`, any `peers.*.routes` (including `domain`, `site_set`, and path-level `override_routes`), `direct`, `allowed_routes`, or `allowed_local_ports` in this mode.

`managed_routes` defaults to `true`. It installs `peers.*.routes` and `direct.routes` prefixes that are not covered by the local TUN subnet. Prefixes within the directly connected TUN subnet still participate in Tinect's internal route selection but are not redundantly added to the system routing table. To prevent a default overlay route from capturing carrier traffic, the daemon creates and tracks underlay host routes only for peer endpoints without a more specific route. Existing administrator-managed routes remain unchanged, and shutdown removes only routes created successfully by this daemon. With `managed_routes: false`, TUN and internal route selection continue to work, and the operator's policy routing must direct traffic into the TUN. On Linux, `fwmark` can be combined with `ip rule` to keep QUIC carrier packets out of the overlay. `carrier_interface` is macOS-only; `fwmark` is Linux-only.

`nft_healthy_set` is a Linux-only configuration object. `prefix` derives `_v4` and `_v6` set names; explicit `v4` or `v6` names take precedence. Tinect creates the target `inet` table and any missing set through `libnftnl`/`libmnl`. Both `destroy_set` and `destroy_table` default to `false`; when set to `true`, Tinect removes the configured set or table at shutdown even if it did not create that object. Tinect maintains an `interval` set containing healthy peer-route prefixes and explicitly configured `direct.routes` prefixes. The administrator must add nft prerouting/output rules to match the set, mark matching packets, and use existing policy routing to direct them to the TUN. When this option is absent, Tinect performs no health-set nft operations. Native fallback is controlled separately by `direct.fallback`.

`direct` is supported only on Linux. Defining the object enables the local machine as an egress candidate; `fallback` defaults to `false`. `direct.routes` uses the same mutually exclusive `ip_cidr`, `domain`, and `site_set` selectors and priorities as peer routes. The local egress is ranked alongside healthy peers for the longest-prefix match or all matching domain candidates. Its priority must be strictly higher to win; overlay routes win ties. If no peer candidate is available, the local machine is considered only when `fallback: true`.

After a local candidate or fallback is selected, Tinect validates the IPv4/IPv6 packet, deletes its first-pass conntrack entry from the default zone through ctnetlink, preserves ECN, adds a marker, and reinjects the packet into the TUN. Parsing or netlink failures fail closed and prevent reinjection. Tinect drops a marked packet if it re-enters its TUN, preventing loops. The local direct egress does not apply egress ACLs. `dscp` must be in `0..=63`; avoid common values such as `46` and `34`, which could make ordinary traffic look like reinjected traffic and be dropped. `conntrack_zone` must be a non-zero `u16` exclusive to this instance; sharing a zone between instances can break each other's NAT. The top-level `fwmark` (`SO_MARK` for the carrier) and `direct.fwmark` (mark for reinjected packets) have different meanings; both must be non-zero and they must differ. When `direct.fwmark` is set, Tinect creates and removes a dedicated `inet` table and prerouting/forward/output base chains at priority `-150` through `libnftnl`/`libmnl`, without invoking the `nft` command or modifying user-owned nft objects. The mark is reserved for direct traffic, and Tinect drops marked packets whose next hop is its own TUN.

When `managed_routes` is enabled (the default) and `direct` is configured, Tinect creates a dedicated `inet` POSTROUTING NAT table (`tinect_direct_nat_*`, priority `150`) through `libnftnl`/`libmnl`. It masquerades reinjected packets by `direct.fwmark` when configured, or by their TUN source address otherwise. Priority `150` runs after regular srcnat at priority `100`, so administrator-configured SNAT/masquerade rules run first. This rule is a fallback.

The same packet first enters the TUN and is then reinjected with the same tuple, but nftables NAT rules are evaluated only for the first packet in a conntrack flow. Tinect uses ctnetlink's `CTA_ID` guarded delete to remove the default-zone flow precisely, then uses a raw PREROUTING rule at priority `-310` to set `ct original zone` to `conntrack_zone`. The reinjected original direction enters the exclusive zone while the reply direction remains in zone 0. This lets Tinect or administrator NAT rules see a new first packet without changing conntrack state for ordinary overlay traffic. Tinect flushes the zone at startup and shutdown and removes the matching zone flow precisely when traffic returns from direct fallback to the overlay.

With `managed_routes: false`, Tinect does not install automatic masquerade rules or operating-system routes, but still runs the ctnetlink worker and installs the directional conntrack zone. The operator configures NAT and policy routing: direct selected traffic into the TUN, route reinjected packets to the default egress, and apply SNAT/masquerade to those packets in the default egress's postrouting chain. See `tests/remote_direct_fallback_unmanaged.sh` for an example.

`runtime.status_socket` is a native-only Unix socket. `runtime.metrics_listen` must be the loopback
address (either `127.0.0.0/8` or `::1`). PCAP contains the decrypted inner IP payload,
`pcap_buffer_packets` remains `0` by default (off), and the upper limit is `65536`.

`path_migration` controls bounded migration after a preferred path recovers. Tinect selects the first ready candidate in `peers.<destination>.paths` order or from automatic path finding, waits for `readiness_stability_secs`, then starts migration. It must complete the signed Open/OpenAck exchange, session installation, and conditional commit within `deadline_secs`. After a successful switch, the old Circuit remains for at most `drain_timeout_secs`. On failure, status shows `MigrationOverdue`, the preferred and current paths, and the recent error; Tinect retries within bounded limits. Circuit migration protects path establishment. TUN packets are not pinned to an old egress by their five-tuple; each packet is selected from currently healthy candidates, so a recovered higher-priority egress takes effect immediately.

`dns_servers` is an optional custom DNS upstream list, the service address must be IP literal, and
the port can be omitted (default `53`). It is used for the hostname in `peers.*.endpoints`; the
daemon attempts to customize the server in order, and falls back to the system resolver after all
failures. DNS uses plain UDP, with TCP fallback when responses are truncated; queries are not
initiated by literal IPs. `listen` must still be literal `IP:PORT`, and DNS upstream changes require
a daemon restart.

## Peer, dialing and routing

`peers.<name>.routes[]` and `direct.routes[]` use object form. Each item must contain exactly one of `ip_cidr`, `domain`, or `site_set`; legacy fields and bare CIDRs are rejected. `priority` defaults to `100`, and higher values have higher priority. Peer routes also support `bind`, which defaults to `false`. Only an `ip_cidr` peer route can set `bind: true`, which binds that CIDR to the peer identity. `domain`, `site_set`, `direct.routes`, and `override_routes` do not create source-address bindings. IP-only `site_set` entries do not require FakeIP; `domain` entries and `site_set` entries containing domain names require `fake_ip`.

Source-address binding is conditional. The receiver combines every peer's `bind_addresses` and routes with `bind: true` into an `IP/CIDR → one or more peers` mapping. If a source address matches no binding CIDR, its source peer is unrestricted. If it matches, only the end-to-end identities in the binding list are allowed. Multiple peers may bind the same CIDR, and overlapping CIDRs allow the union of their identities. Binding is checked only at the final decryption node; relays do not decrypt or perform this check. Do not bind `0.0.0.0/0` or `::/0` unless the entire address family should be restricted to that peer.

A relative `site_set` path is resolved from the directory containing the main YAML file; changes require a daemon restart. Each line uses its first space-separated field and ignores later labels. Supported entries are blank lines, `#` comments, bare domain names, `full:domain`, a wildcard `*` in at most one position per label, and `ip-cidr:<CIDR>`. A bare domain matches itself and all subdomains; `full:` matches only itself. A wildcard matches non-dot characters within one label. `regexp:` and the legacy `.domain` notation are not supported. Any other invalid line causes configuration loading to fail. Each canonical path is read once, and identical canonical content at different paths shares an immutable index.

`fake_ip.listen` provides UDP and TCP DNS. `upstream_dns` must be a non-empty list of IP literals; port 53 may be omitted. Unmatched domains are forwarded locally. When a `domain` or domain-based `site_set` route matches, Tinect gathers healthy peer candidates and matching `direct.routes`, then resolves them in route-priority order. A peer candidate sends the DNS request through a Circuit, and the egress tries its upstream servers in configuration order. A local candidate queries its upstream directly without egress ACL processing. Peer candidates win priority ties. If every explicit candidate fails, Tinect tries the local machine only when `direct.fallback: true`; otherwise it returns SERVFAIL. Tinect records the egress that resolved the domain and sends associated traffic through it first. If that peer becomes unhealthy, it ranks the currently healthy peers and explicit local candidates again. If none are available, `direct.fallback: true` allows FakeIP to resolve to the real destination and send traffic locally; otherwise the request fails closed. A and AAAA queries return FakeIP only after Tinect obtains a real address of the same family. HTTPS, SVCB, and ANY return NODATA. With `disable_ipv6: true`, AAAA, HTTPS, and SVCB also return NODATA. Default FakeIP pools are `198.18.0.0/15` and `fd74:696e:6563:7400::/64`; TTL is clamped to 60–86,400 seconds.

Each `peers.<exit>.upstream_dns` can override the global `fake_ip.upstream_dns`; a manual path's `override_upstream_dns` can override the exit value. The precedence is active path → exit peer → global setting. Explicit overrides must be non-empty lists of IP literals and require `fake_ip` to be configured. The effective value is fixed when a Circuit lease is established and changes atomically only after a new lease is committed, so DNS settings from different paths are not mixed while the old lease drains. Native queries for `direct.routes` and `direct.fallback` always use the global value.

FakeIP does not require an alias pool. For secure Circuit traffic, the source maps `original source → FakeIP` to `node-side TUN source address → real destination`. Local direct traffic temporarily uses `FakeIP → real destination`. FakeIP is a local return anchor for POSTROUTING NAT and is masqueraded before leaving the node. The source stores the original address locally and uses TCP/UDP ports or the ICMP identifier to distinguish flows. Only secure Circuit forward packets carry a self-describing FakeIP envelope inside the end-to-end encrypted payload. The egress strips the envelope and creates a return flow associated with the source Circuit; ordinary Forward packets carry no extra payload or state. Network return packets preserve `real destination → node-side TUN source address` and follow the original Circuit. Direct return packets are matched against the local FakeIP wire flow. The returned envelope is used only at the source to restore `FakeIP → original source`; it does not affect remote node or path selection. The FakeIP pool is valid only on the source node and should not be installed at the egress. An egress or relay only needs to route replies to the source node's TUN address. Unknown protocols work only when their flows can be matched unambiguously. With `managed_routes: false`, the operator must route the node-side TUN address. Mappings do not survive a restart; old FakeIP and return flows fail closed until a new lookup creates a mapping.

Each `peers.<name>` must provide a canonical Base64-no-pad `public_key` and an `endpoints` array, with no leading or trailing whitespace. The same public key cannot be configured under multiple peer names. `bind_addresses` defaults to `[]`; it declares source-address ownership but does not change destination routing. `accept_connections` allows only registered peers to establish inbound Links; unknown public keys are always rejected. `allow_transit` controls whether known sources can establish and use Circuits through this node. `allow_relay` defaults to `false` and independently controls whether that peer can carry traffic with an unknown source or destination.

Each physical Link uses DPLPMTUD or authenticated probes to measure capacity for its carrier. The Link converts differences in QUIC DATAGRAM, bare UDP receive IDs, and the fake-TCP outer layer into the maximum complete user IP packet size, then advertises directional `inner_mtu` in signed topology updates. A multi-hop path uses the minimum capacity of its edges. `tun.mtu`, Circuit send budgets, and route-binding MTUs all use complete user IP packet bytes; the send boundary accounts for Tinect's fixed Forward overhead. Missing or expired advertisements use a conservative capacity. The legacy `peers.*.pmtu` field has been removed and is rejected. Each `ip_cidr` must be a CIDR; higher `priority` values win. Multiple peers may advertise the same prefix and become candidate egresses.

`connect_to` controls active dialing only; listing an endpoint under `peers` does not initiate a connection automatically. Each `peers.<destination>.paths[]` item must contain `path`. A path must start with the local `id`, end with the destination, contain at least two nodes, and have no loops. Every intermediate node must be a configured peer. When a manual path is configured, Tinect does not perform automatic path finding for that destination.

Each manual path can specify `override_routes`. An item with `ip_cidr`, `domain`, or `site_set` matches only the same selector declared by the destination. If no selector matches, `priority` adds a candidate route for the destination. `priority: 0` disables a candidate. An item with no selector applies to all routes declared by that destination. `priority` and `priority_delta` are mutually exclusive; a delta that results in a priority less than or equal to zero disables the candidate. A new selector-based item must specify a priority rather than only a delta. Overrides take effect only when the path becomes active; the old path's overrides remain active until migration completes.

The destination of `path_policies` must also be a configured peer; it only constrains the automatic
path: `prefer_via` is prioritized, `require_via` and `avoid` are hard constraints, and `max_hops`
limits the maximum number of hops. Nodes publish signed Link-State advertisements every 15 seconds,
and the advertisements are valid for 50 seconds.

## Egress ACL

`allowed_routes` controls forwarding to destinations other than this node's TUN addresses. Configuring
any rules makes this node an egress and enables forwarding and NAT. `allow` must contain at least one
CIDR; `deny` is optional and evaluated first. Before configuration, host IP forwarding must be
permanently enabled by the system administrator: Linux settings `net.ipv4.ip_forward=1` and
`net.ipv6.conf.all.forwarding=1` (for example, write `/etc/sysctl.d/99-tinect.conf` and then execute
`sysctl --system`); macOS settings `net.inet.ip.forwarding=1` and `net.inet6.ip6.forwarding=1`.
Tinect only verifies these preconditions and never modifies them on startup or exit; it only creates
and cleans up NAT/firewall resources it owns.

`allowed_local_ports` controls the protocols and ports allowed to reach this node's TUN addresses
and can be configured independently of `allowed_routes`; it does not control remote DNS queries
within a Circuit. `allow` must contain at least one selector, and `deny` takes precedence. Selectors can be `all`, `tcp`, `udp`, `icmp`, `icmpv6`, `tcp(PORT)`, `udp(PORT)`, `tcp(FIRST:LAST)` or `udp(FIRST:LAST)`. To avoid
port forgery with fragmented payloads, all inner IPv4/IPv6 fragments are rejected on the egress;
avoid relying on inner IP fragmentation via path MTU and MSS clamp.

For both ACLs, `for` can be a list of node names, a list containing only negated node names (such as
`["!blocked-node"]`), `any_known`, or `any_inc_unknown`. The list cannot be empty, and cannot mix
normal names and `!` negative names; `allowed_routes.for` is an empty list when omitted, so it
should be configured explicitly, and `allowed_local_ports.for` defaults to `any_known` when omitted.

When `allowed_local_ports` is not configured, native TUN delivery defaults to allowing all
protocols/ports, but only known sources. The daemon does not support hot reloading, and the service
needs to be restarted after modifying any configuration field.

## Defaults and FEC

`repair_rate` is the maximum average number of repair datagrams per source datagram; fractional
values are allowed. `0` disables FEC, and any non-zero value must be at least `0.001`. The sender
uses a long-term average and a credit budget tied to the current source burst. If the repair window
is full, it cannot send another full-window repair. Unsent repairs return their credit and are
retried with bounded backoff. The active side uses the value in its `connect_to` entry, while the
passive side uses the top-level value. A Link uses the lower of the two values, and FEC is enabled
only when both are non-zero. FEC works independently on each physical Link; relays never decrypt
the end-to-end payload.

After enabling FEC, Link will reserve additional capacity for the worst-case repair packet: the IP
capacity of ordinary users is calculated as the physical capacity minus `66` bytes, and the FEC Link
is calculated as the physical capacity minus `82` bytes. When FEC is turned off, the original packet
format and `66` byte overhead are still used, and no additional packet space is occupied.

| Field | Default Value |
| --- | --- |
| `accept_connections` / `allow_transit` | `true` / `false` |
| `managed_routes` / `tun.enabled` | `true` / `true` |
| `nft_healthy_set` (`prefix` / `v4` / `v6`) | Not set (off) |
| `nft_healthy_set.destroy_set` / `destroy_table` | `false` |
| `direct` | Not set (off) |
| `direct.fallback` / `direct.routes` | `false` / `[]` |
| `peers.<name>.bind_addresses` / `peers.<name>.routes[].bind` | `[]` / `false` |
| `tun.mtu` / `tun.clamp_mss` | `1280` / `true` |
| `link_health` | `keepalive_secs=10`,`idle_timeout_secs=35`,`reconnect_interval_secs=2` |
| `path_migration` | `readiness_stability_secs=1`,`deadline_secs=5`,`drain_timeout_secs=1` |
| `repair_rate` | `0` (turn off datagram FEC) |
| `runtime.pcap_buffer_packets` / `shutdown_timeout_secs` | `0` / `10` (pcap upper limit `65536`) |
| `dns_servers` | `[]` (using system resolver) |
| `fwmark` / `direct.fwmark` | Not set; must be non-zero when configured and must not be equal |
| OPEN path hop count | The upper limit is `16`. OPEN exceeding the limit is rejected by `InvalidPath` |
| Circuit DNS | source pending upper limit `256`, single response maximum `64` chunk, each chunk `900` bytes, total `65535` bytes |

`link_health.keepalive_secs` must be non-zero, `idle_timeout_secs` must be greater, and
`reconnect_interval_secs` must also be non-zero. This cycle renews the locally signed LSA and sends
deltas over the reliable control stream; a new Link exchanges complete, chunked Snapshots. When
the actual QUIC adjacency is idle, it will also send physical keepalives that are encrypted and
identity bound but do not contain topology; ordinary forwarding data also refreshes the physical
active time. Failure to receive a valid physical payload for `idle_timeout_secs` (default 35
seconds) will mark the peer as unhealthy, close the link and trigger path recalculation. QUIC
transport keepalive is only a lower-layer fallback. `status.links[].healthy` and
Prometheus `tinect_links_healthy` expose peer health; Circuit lease renewal,
feedback and data plane sending results further maintain the health of path binding. Each active
connection attempt (including DNS, QUIC and identity handshakes) lasts up to 5 seconds. After a
timeout or when a closed Link remains, the daemon retries according to the reconnect backoff, which
is capped at 5 seconds after consecutive failures. The
configuration is immutable after startup, and any modification requires restarting the daemon. The
old `health_checks.*.targets` native TCP service probe has been removed and will be rejected if
`health_checks` appears in the configuration.
