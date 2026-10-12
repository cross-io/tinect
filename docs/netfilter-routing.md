# Linux Netfilter and Routing Behavior

This document is intended for administrators who need to configure nftables rules or routes locally.
It explains which netfilter (nftables) resources and routes Tinect creates and manages on Linux, at
what priority they run, how they interact with the administrator's own rules, and what administrators should consider during configuration. All resources directly construct netlink messages through
`libnftnl`/`libmnl`/`rtnetlink`. The runtime does not depend on the `ip` or `nft` command line
program; the daemon only deletes the tables it creates and does not modify user objects.

## Resource overview

| Configuration | Resources (`<hex>` is the TUN name in hexadecimal) | Content | Installation conditions |
| --- | --- | --- | --- |
| overlay routing | system routing table (rtnetlink) | prefixes in `peers.*.routes` that are not covered by the local TUN network segment → `dev <tun>` | `managed_routes: true` |
| egress ACL | `tinect_exit_<hex>` (`ip`/`ip6` two tables with the same name) | forward-chain acceptance and POSTROUTING masquerade | `allowed_routes` non-empty |
| TUN inbound | `tinect_input_<hex>` (two tables with the same name, `ip`/`ip6`) | INPUT priority -200 allows TUN inbound | Always (Linux) |
| Health routing set | User-configured table/set | `_v4`/`_v6` set elements with `interval` flag | `nft_healthy_set` |
| direct fallback | `tinect_direct_<hex>` (`inet` table) | prerouting mark, forward/output loopback protection | `direct` |
| fallback conntrack/NAT | `tinect_direct_nat_<hex>` (`inet` table) | PREROUTING directionality zone; optional POSTROUTING masquerade | `direct` |

Except for overlay routing, all other resources will be deleted from the entire table when the
daemon exits normally and initiates rollback (overlay routing is recycled according to the
installation list). When `managed_routes: false` is set, the daemon does not install overlay routing
or automatic masquerade, but still installs the direct fallback directional conntrack zone; routing
and NAT are the responsibility of the administrator.

## Hook priority and timing

Each base chain of nftables is executed sequentially according to the hook priority in the same
netns (the one with the smaller number is executed first, and the `accept` judgment will terminate
the subsequent base chain):

```text
raw -300 → conntrack -200 → mangle -150 → dstnat -100 → filter 0 → srcnat 100
```

Non-default priorities used by Tinect:

- TUN inbound INPUT: `-200`, precedes the user INPUT chain to ensure that overlay return packets
  are not mistakenly blocked by user INPUT rules (acceptance judgment terminates subsequent
  chains).
- direct fallback prerouting/forward/output: `-150` (mangle segment), precedes the ordinary filter
  chain.
- The raw chain of the direct fallback zone: `-310`, precedes the regular raw chain and conntrack,
  and specifies an exclusive zone for the original direction of the reinjected packet.
- exit masquerade: `100` (regular srcnat); direct fallback masquerade: `150`, located after the
  regular srcnat, the administrator's own SNAT/masquerade rules take precedence.

## Resource details

### overlay routing

When `managed_routes: true` (default), the daemon writes the prefix in `peers.*.routes` that is not
covered by the local TUN address network segment into the system routing table through rtnetlink,
and the next hop is the TUN device. Prefixes covered by the local TUN directly connected network
segment still participate in Tinect's internal routing selection, but will not be repeatedly written
into the system route. When `managed_routes: false`, TUN and internal routing still work, traffic
should be sent to TUN by the administrator's own policy routing.

On Linux, it is recommended to use `fwmark` + `ip rule` to prevent QUIC/QUIC-full carrier packets
from being routed back into the overlay: Set a mark for the physical socket, and then add a routing
table pointing to TUN for the overlay target network segment. The rule is consumed according to
`from all fwmark <mark> lookup <table>`. This mark and `direct.fwmark` are two different marks and
are unrelated to each other.

### Egress firewall (`tinect_exit_<hex>`)

Installed only when `allowed_routes` is configured (`allowed_local_ports` itself does not trigger
this table), `ip` and `ip6` have two family tables with the same name:

- `forward` (filter, priority 0): `iifname <tun> && oifname != <tun>` pass, allowing encrypted
  egress traffic forwarded from TUN to pass the user FORWARD policy.
- `postrouting` (nat, priority 100):
  - Encrypted egress traffic masquerade for `iifname <tun> && oifname != <tun>`;
  - Match the source address by TUN address exact/prefix rules (`ip saddr` / `ip6 saddr`),
    covering the path where the fallback packet no longer carries the TUN incoming interface
    mark after leaving TUN.

When the priority (100) is the same as the user rule, nft is executed in the base chain registration
order; if you need to give the user masquerade priority, put the user chain in the table created
earlier or with a lower priority.

### TUN inbound (`tinect_input_<hex>`)

`ip` and `ip6` family tables with the same name each have an `input` chain (filter, priority `-200`) that accepts
inbound packets from TUN. The priority precedes the user INPUT chain, and the `accept` decision
ensures that the overlay return packet will not be mistakenly blocked by the user INPUT policy when
it is delivered to the local socket; the user can still impose policies on outbound/forwarded
traffic at a lower priority.

### Healthy routing set (`nft_healthy_set`)

The administrator configures `prefix` (or explicit `v4`/`v6`) with the target table. The daemon
creates two sets `_v4`/`_v6` with the `interval` flag in the target `inet` table (created if
missing), only updates the healthy routing prefix elements, and never modifies user rules, marks or
policy routing. `destroy_set`/`destroy_table` defaults to `false`; exiting when set to `true` will
destroy the set/table in the configuration. Administrators write their own prerouting/output rules
to consume set and set mark, and then policy routing sends the hit traffic to TUN.

### Direct-fallback firewall (`tinect_direct_<hex>`)

The `inet` table contains filter chains only:

- `prerouting` (priority `-150`): for packets matching `iifname <tun>` and the marker DSCP, set
  `direct.fwmark`, clear DSCP (retain ECN). The reinjected packet is a new skb and its mark
  is always 0, so the loopback cannot be recognized here.
- `forward`/`output` (priority `-150`): Packets carrying this mark and whose next hop is this TUN
  (forwarded or locally generated) are dropped before re-entering the TUN to prevent unlimited
  back-injection caused by incorrect policy routing. `fwmark: 0` is the kernel's default mark and
  cannot be distinguished from ordinary unmarked packets, so the configuration verification
  directly rejects it.

This mark is exclusive to direct fallback and does not support mask; users are not allowed to use
the same mark for normal traffic.

### Fallback conntrack and automatic masquerade (`tinect_direct_nat_<hex>`)

Install the `inet` table when configuring `direct`:

- `prerouting` (filter, raw priority `-310`): Matches IPv4/IPv6 back-injection packets inbound
  from TUN and carrying the marker, sets `ct original zone set <conntrack_zone>`. The reply
  direction remains zone 0, and the normal ingress returns the packet so the NAT flow can be
  found.
- `postrouting` (nat, priority `150`, only when `managed_routes: true`): When `fwmark` is configured,
  match the reinjected packet by `meta mark`; otherwise match it by the TUN source address to
  match; masquerade packets with `oifname != <tun>`. After the regular srcnat (100), the administrator's
  SNAT/masquerade rules take precedence.

#### Why ctnetlink + directional zone is needed

The nftables NAT chain only performs rule search on the first packet of each flow, and subsequent
packets directly reuse the NAT binding established by the first packet. The fallback packet passes
through the kernel protocol stack twice with the same five-tuple (first entering TUN, and then
back-injecting). The first pass will create a conntrack flow; if not processed, the back-injection
packet will be skipped by the NAT chain as a whole, and masquerade will not take effect.

Before back-injection, the daemon queries the default zone 0 through the long-term ctnetlink socket
according to original/reply tuple, reads `CTA_ID`, sends the precise deletion of tuple + zone + ID
and waits for ACK. ID prevents the new flow from being mistakenly deleted when the same tuple flow
is replaced between query and deletion; `ENOENT` is the idempotent success, and other errors are
fail closed, and the current packet is not returned. Then the raw chain only puts the original
direction of the back-injection skb into the exclusive zone. Even if the old skb is late and
reconfirms the zone 0 flow, it will not prevent the back-injection flow from executing the NAT first
packet rule, nor will it change the conntrack status of the ordinary overlay first pass.

`conntrack_zone` must be non-zero u16 and owned exclusively by a Tinect instance. When the daemon
starts and exits, the zone will be flushed through ctnetlink, and the corresponding zone flow will
be accurately deleted when switching back to a healthy overlay from fallback. Tuple parsing, netlink
rejection or timeout will discard corresponding packets; the fallback flow collection in memory has
a fixed upper limit and refuses to accept new items when old items cannot be cleaned up.

## Relationship to Admin Rules/Routes

- All nft tables created by daemon start with `tinect_` and have the hexadecimal suffix of the
  interface name. The entire table will be deleted during normal exit, SIGTERM and rollback
  startup, without modifying the user object; overlay routes will be recycled according to the
  installation list, and user routes will not be touched.
- User NAT always takes priority: the direct fallback chain is at priority 150, and the exit chain
  is at 100.
- The administrator needs to configure the `ip rule` that consumes `direct.fwmark` and the policy
  routing table (for example, routing the injection packet to the default exit), and send the
  traffic that needs to enter the TUN into the TUN (health set rules or policy routing).

## Safety and operational considerations

- Do not rely on or modify native default routes controlled by other network management policies;
  Tinect only installs/recycles its own declared overlay prefixes.
- `direct.fwmark` is exclusive to this function; it is a different concept from the `fwmark` of
  the carrier socket and the mark of the policy routing. Please pay attention to the distinction
  when configuring.
- `direct.conntrack_zone` must also be exclusive and must not be reused with a VRF, container,
  other Tinect instance, or administrator's nftables zone rules.
- PCAP contains plain text inner IP payload, which is turned off by default; the management status
  socket is only bound to the local machine.
- When modifying the frame format, encryption, ACL, routing or hot reloading semantics,
  `README.md`, `docs/config.md`, `docs/architecture.md` and related RFCs need to be updated
  simultaneously, and tests covering successful and rejected paths need to be added.
