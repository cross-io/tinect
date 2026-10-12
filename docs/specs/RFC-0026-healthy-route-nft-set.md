# RFC-0026: Healthy routing network segment nft set

- Number: RFC-0026
- Status: Implemented
- Created: 2026-08-08
- Last updated: 2026-08-09

## Summary

RFC-0032 defines a direct-reinjection mechanism that coexists with this RFC, and RFC-0033 allows
explicit `direct.routes` to make the local machine an always-available routing candidate. The
healthy set therefore represents destination prefixes that Tinect can currently handle: healthy
overlay prefixes and explicitly configured direct prefixes are included. Enabling only
`direct.fallback` does not add otherwise undeclared prefixes. These nftables resources have
independent lifecycles.

This RFC replaces the `local_route_fallback` raw-IP implementation with a Tinect-maintained set of
destination prefixes that the current configuration and healthy routes can handle. The administrator
configures an nftables set for IPv4, IPv6, or both. Tinect adds a route prefix while it has at least
one healthy candidate for that prefix and removes it when no healthy candidate remains.

Tinect no longer sends unsupported IP packets through a local raw socket, and no longer creates raw
sockets, rewrites source addresses, performs local NAT, or provides a local egress fallback. The
administrator writes nftables rules that mark packets matching the healthy-prefix set, then uses
existing `ip rule` and policy routing to send them to TUN. Packets that do not match the set bypass
Tinect and follow the system's other routes, default route, or administrator-provided fallback.

## Background and Problem

The old `local_route_fallback` dataplane first sent packets into TUN according to policy routing.
When Tinect found no healthy overlay egress, it sent the packet from the local machine through a
Linux or macOS raw-IP socket. This design has several structural problems:

1. Raw-IP injection bypasses the conntrack and return-path association provided by ordinary
   UDP/TCP sockets. Rewriting the source address may work for connectionless traffic such as ICMP,
   but UDP/TCP replies cannot be reliably delivered to the original socket or client.
2. Tinect must own local egress selection, source-address selection, checksums, interface binding,
   packet marks, NAT, and failure cleanup. As a result, a send can appear successful even though
   the reply is unreachable.
3. Sending every packet to TUN before deciding whether it should leave the overlay makes Tinect
   handle traffic it should never have received and couples policy routing, NAT, and reinjection.
4. Tinect already computes route health from its route snapshot, Circuits, and Link health. Host
   policy routing cannot consume that information directly, so the old design made Tinect select
   again after the packet had entered TUN.

The new design moves the decision about whether a packet should enter Tinect to nftables packet
classification in `prerouting` and `output`. Only packets matching a healthy-prefix set receive a
mark and enter Tinect's routing table. Health changes update set elements without changing the
administrator's nftables rules, `ip rule`, routing tables, or default route.

## Goals and non-goals

### Goals

1. Remove all `local_route_fallback` Related raw-IP sending, source address rewriting, native fallback
NAT and fallback dedicated interface binding implementation.
2. Allow users to pass `nft_healthy_set.prefix`,`nft_healthy_set.v4` and
   `nft_healthy_set.v6` Configure the IPv4/IPv6 nft set maintained by Tinect and pass
   `destroy_set`/`destroy_table` Explicitly configure object destruction on exit.
3. Create the specified set when it does not exist; perform strict type and ownership verification when the set already exists.
4. Continuously maintain the current healthy routing network segment: when there is at least one healthy Tinect routing candidate for a certain prefix,
This prefix should be present in the set; otherwise it should be removed.
5. Use nftables atomic transactions to update elements so that user rules do not observe half-updated network segment collections.
6. Maintain user control over nft mark, ip rule, policy routing table, TUN routing and non-Tinec fallback.
7. in `managed_routes: false` The set can still be maintained; Tinect does not gain management rights to the routing table.
8. Before introducing set health status consumption, fix the link health status in status and the actual current Link/Circuit
State inconsistency problem; state display, health collection and data surface must use the same set of health state sources.

### Non-target

- The user's nft chain, rule, mark, ip rule or policy routing is not created, modified or deleted by Tinect.
- The host's IP forwarding, default route, or policy routing tables are not set or cleaned up by Tinect.
- No propagation of nft set elements to the remote end, no changes to Circuit, Physical, topology, or encrypted wire formats.
- Do not treat set as security authorization, ACL, or peer identity verification; set only expresses local routing hints.
- New Tinect native egress capabilities are not provided for packets with "no healthy Tinect routes".
- Cross-namespace nft set management is not implemented in this RFC; the set must be located in the directory where the Tinect daemon is running
  network namespace.

## Terminology and data model

- **Healthy route prefix**: A target CIDR in the current route snapshot, at least one of which can be sent
Healthy route binding.
- **Candidate Link**: A Tinect egress candidate corresponding to a route prefix and its current active Circuit/path.
A multi-hop path is considered a healthy candidate only if both the local link and circuit binding required for its transmission are healthy.
- **Health Set**: The set of all healthy route prefixes, calculated separately for IPv4 and IPv6.
- **Management set**: An nft named set of elements specified by configuration and maintained by Tinect. The user owns a reference to the set
rules; Tinect has the life cycle of set elements.
- **qualified set identity**:`table:name`2-tuple. This RFC permanently uses nft `inet` table;
Therefore, the combination of table name and set name can uniquely locate a set. Element types for IPv4/IPv6 are maintained by
Determined by the address family.

## Configuration semantics

### Configuration format

Added Linux-specific optional `nft_healthy_set` Object:

```yaml
# Automatically maintain when configuring prefix:
# router_policy:tinect_healthy_v4
# router_policy:tinect_healthy_v6
nft_healthy_set:
  prefix: router_policy:tinect_healthy
# It can also be specified explicitly by address family; explicit fields only cover the corresponding address family.
  # v4: router_policy:tinect_route_v4
  # v6: router_policy:tinect_route_v6
  destroy_set: false
  destroy_table: false
```

Configuration values   must strictly comply with `<table>:<name>` Format: Contains exactly one ASCII `:`, both sides are non-empty
nft identifier.`<table>` yes `inet` table name,`<name>` is the set name; this RFC does not support the
This value carries `ip`,`ip6` Wait table family. Disallow empty strings, NUL, control characters, whitespace, extra
Colons and characters that cannot be represented by nft. All three address fields are verified according to the same rules; even if a field will eventually be
Another field override, formatting errors must also be reported as configuration errors and cannot be silently ignored.

`destroy_set` and `destroy_table` Both are optional boolean values, default `false`. They only control whether on exit
Destroy the set/table in the configuration without making additional judgments based on whether the object was created by Tinect; therefore turning on the switch means
It is the caller's express responsibility to delete these objects and their dependencies.

The target set after configuration parsing is generated family by family according to the following rules:

| Address Family | Yes `nft_healthy_set.prefix` Default value when | Explicitly override fields |
| --- | --- | --- |
| IPv4 | `{table}:{prefix}_v4` | `nft_healthy_set.v4` |
| IPv6 | `{table}:{prefix}_v6` | `nft_healthy_set.v6` |

where prefix of `<table>` and `<prefix>` respectively from `nft_healthy_set.prefix` of two parts.
If an explicit field exists in an address family, the explicit value takes precedence; the explicit field can use a table different from the prefix.
Without prefix and only explicit v4/v6 fields, only configured address families are maintained. When none of the three fields are configured,
Completely turns off nft set maintenance and does not perform any nft-related platform I/O.

The derived name must again pass the nft identifier check; so for example the prefix itself is legal but the concatenation `_v4` or
`_v6` When the name limit is exceeded, it is also a configuration error. The same one in the parsing result `table:name` Not at the same time
Targeted by both IPv4 and IPv6 sets because the element types of the two sets are different; this is a configuration conflict.

if target `inet` The table does not exist, Tinect creates it with the exact table name in the configuration; no other tables are guessed.
User rules and chains are still the responsibility of the administrator; the exit destruction of table/set is completely controlled by two destroy switches.

### Configuration verification and compatibility

New configurations cannot be mixed with old fields.`local_route_fallback` and `local_route_fallback_if` exist
Implementation of RFC-0026 should be removed from the configuration model; old fields must be given an explicit error when present in the configuration and cannot
Silently ignored or converted to nft set.

three `nft_healthy_set_*` Field is only valid on Linux. When configuring any field on macOS, it should be in the parsing/verification stage
Rejected because this RFC only defines the nftables backend and does not convert it into PF rules.

What this configuration changes is the pre-classification method of local packets entering TUN. It does not belong to the protocol wire compatibility change, but it will
Changes the runtime semantics of the old fallback configuration, thus requiring an explicit migration and restart of the daemon.

## Calculating healthy prefixes

### Prefix source

The health set is derived from the currently effective route snapshot, rather than the static CIDR list of the original YAML. so
can correctly reflect:

- `peers.<name>.routes` valid route;
- Current activity path and `override_routes` valid candidates after;
- Longest prefix and multiple candidates with the same prefix;
- Whether the Circuit has been established and bound to the sendable data plane;
- Link health status, connection closure and path migration submission results.

Native TUN address, only used for Tinect internal routing but no prefix to send binding, and has been lost
The prefix of all health candidates, not added to the health set. The source of the prefix does not include the old `local_route_fallback`
list as it was removed in this RFC In Progress.

### Health Judgment

to a normalized prefix `P`,definition:

```text
healthy(P) = exists candidate C for P:
  C has a current route binding
  and C's active Circuit/path is usable
  and C's required local/physical link health is true
```

The existence of a healthy candidate suffices `P` Put in a set; all candidates are not required to be healthy. When a healthy candidate is restored,
`P` should reappear; when the last healthy candidate expires,`P` should be deleted.

The health status is based on the immutable route snapshot submitted by Tinect and will not be reset in the nft update thread.
Parse configuration or perform routing. The set calculation for set must use the same version of health as the route snapshot
Candidate to avoid a window where the set has been declared healthy but the corresponding binding is not yet sendable.

### Link-state display consistency (prerequisite fix)

The current Link-status display has a known bug and must not drive the healthy set until it is
fixed. Before implementing this RFC, make the following state reporting consistent:

- `LinkStatus.healthy` must reflect currently registered Link instances, not merely the latest
  event received for a peer name. A close or error from an old Link must not overwrite the state of
  a newer Link for the same peer.
- Link-state events must include the Link instance identifier, or an equivalent generation/epoch.
  Consumers must verify that an event still refers to the current instance. Tests must cover
  disconnect, replacement, and reconnection ordering.
- Define a clear mapping between the health shown in status output, the candidate health reference
  count, and candidate availability in the route snapshot. Status and the healthy set must not
  disagree about whether a candidate is available.
- During reconnection, delayed shutdown of an old instance, Circuit/path migration, and health-check
  failures, status, routes, and the healthy set must converge on the same current state. Discard
  stale events whose ownership cannot be verified, and log enough context to diagnose them.

This is a prerequisite for accepting RFC-0026; retries or periodic full scans at the set layer do
not fix inconsistent Link-state events. Implement the event-model correction first, then feed the
same event stream to the healthy-candidate counter.

### Overlapping prefixes

Every healthy route prefix may be represented in the set. For example, `/0` and a healthy `/32` can
both be present in the logical set. nftables interval sets may canonicalize or merge overlapping
and adjacent intervals as long as the resulting address membership is equivalent. Removing `/32`
must not remove addresses that remain covered by a healthy `/0`.

Route priority does not affect set membership: a prefix is present whenever at least one candidate
for it is healthy. Tinect's route snapshot and dataplane continue to choose which healthy candidate
actually carries each packet.

The implementation represents CIDRs as half-open nft interval ranges `[start, end)`. `start` is
the first address in the prefix, and `end` is the first address after it. The address space wraps
at the maximum address, so `/32`, `/128`, and `/0` require explicit wraparound handling. For `/0`,
`start` and `end` are both zero, represented by one ordinary zero-address element rather than an
interval-end element with the same key. Before writing a batch, remove nested prefixes already
covered by a broader prefix so nft does not misinterpret overlapping ranges as interval markers.
This changes only the set encoding, not the logical set of addresses.

## nft set life cycle

### Startup and Resource Ownership

Tinect uses existing Linux `libnftnl`/`libmnl` netlink control plane, not called `nft` executable file,
Nor parsing `nft list ruleset` text.

This is to implement a hard constraint: must not pass `Command::new("nft")`,shell,`run_checked("nft")` or any
Called by other sub-process methods `nft`. The query, creation, element update and cleanup of table/set must go through
nftables netlink API completed.

At startup, for each parsed `table:name` The target performs the following process. The target table family is fixed to
`inet`, the address family only determines the element type of set:

1. Check the target `inet` Whether the table exists; if it does not exist, it will be created with the exact name in the configuration.
2. Check whether the target set exists.
3. If it does not exist, create a named set, the element type is the corresponding address family, set the interval flag, and record
Documents that this set is currently controllable by the destroy switch.
4. If it exists, verify the table, set name, element type and interval capabilities; if they do not match
Refuse to start, do not delete, do not rebuild, do not change the set.
5. After reading the current element, first perform a full clear; then use the current healthy route snapshot to perform the first
reconcile to avoid retaining old health status across the daemon life cycle.

Existing and type-compatible sets can be used directly as configuration targets; Tinect does not read or write owner userdata,
Nor does the life cycle depend on who originally created the object. When multiple daemons configure the same set at the same time, the behavior is determined by
The user's deployment constraints are responsible for coordination.

### On-the-fly maintenance

Tinect only modifies the elements that manage the set, not the user rules that reference the set. During normal operation, set updates must
It is event-driven and adopts an incremental approach, and cannot recalculate and replace the entire address set due to an unrelated state change.

route refresh worker uses `CircuitOpenManager` The generation/Notify acts as a unified event boundary:
Wait for the next notification after submitting the route snapshot and set increment each time, and do not use fixed period polling. connection established,
Connection closure, topology changes, Circuit/path life cycle, link health edge, and data plane binding
Health edges must trigger this notification; no route snapshot reconstruction or nft set operations are performed without these events.

The health status manager maintains a health candidate count or equivalent set of candidate references for each normalized prefix:

```text
healthy_refcount(P) = number of currently healthy candidates for P
set contains P iff healthy_refcount(P) >= 1
```

The following events must carry affected candidates/prefixes, or the exact difference can be calculated from the old and new route snapshots:

- route snapshot submission: only process prefixes that are added, deleted, or whose candidate health changes;
- Circuit/path establishment, shutdown, migration submission and link health state changes: only the corresponding candidate state conversions are processed;
- Configure route binding changes resulting from hot reloading: only affected old/new prefixes are processed.

Event handler updated by candidate state transition `healthy_refcount`, only if the count spans `0 -> 1` time direction set
Incrementally add prefix, only if count spans `1 -> 0` Removes the prefix when incrementing the set. counting in `1 -> 2`,
`2 -> 1` No nft element operation occurs during conversion; prefixes with different address families are written into the corresponding address family set.
No conversion across sets.

Multiple adjacent events can be coalesced briefly, but the result of the coalescing must still be a delta of the affected prefix
operation rather than a wholesale replacement of the entire health set. A batch can contain add/delete for multiple affected prefixes,
However, you must not clear and rebuild the entire set in order to update one of the prefixes. Event processing must be deduplicated and idempotent, and duplication
Events cannot cause false counts or duplicate set elements.

When initial reconciliation is started, set is deleted/replaced externally, set is restored, and runtime state inconsistency is detected,
Allows a full scan and repair to be performed; these are recovery paths, not normal health change paths. Periodic tasks can only
As a fallback after low-frequency consistency checks and loss events, it must not be used as the only or main triggering mechanism for normal set updates.

### Atomic updates

An incremental update must use an nft netlink batch: performed on the affected prefixes of this batch in the same transaction
add/delete. When an nft transaction fails, the old collection remains unchanged and uncommitted delta events are retained and bounded by the runtime.
Back off and retry; you cannot clear the set first and then add items one by one asynchronously. A complete repair of the boot or recovery path must also be done in a single
Completed in a transaction, the full reconstruction cannot be split into user-observable intermediate status.

The event reducer first updates the expected state and healthy reference count; only after the incremental update is successful, the nft of the corresponding prefix is
Membership is marked committed. Health state can briefly lead or lag behind nft set, but not in Tinect
A failed update was mistakenly recorded internally as a success. The retry must be based on the expected state and committed membership.
When calculating delta, it cannot be assumed that some operations of the failed batch have taken effect.

If the user or other program deletes the set, the periodic repair task should re-perform the existence check:

- table still exists and set type is correct: recreate and fully reconcile;
- The table does not exist or the object type with the same name is incorrect: enter degraded state, retain diagnosable errors, and do not delete
User objects also do not execute raw-IP fallback;
- Tinect should not rebuild the user table or user rules while the user deletes/modifies the set.

### Stop, exit and abnormal termination

When exiting normally, Tinect first clears the managed elements; then only if `destroy_set: true` When deleting the configuration
set only if `destroy_table: true` Delete the table in the configuration. The object is retained when both switches are false.
If the deletion fails (for example, there are still external references), only a warning will be logged, and the rule that refers to it will not be deleted to delete the set/table.
or chain.

Immediate cleanup is not guaranteed on abnormal termination. The next launch will clean up old elements with a full reconcile. implementation stage
Using nft element timeout should be evaluated as additional crash protection; if the kernel does not allow it
The combination of interval set and timeout will not use timeout as a necessary dependency of RFC-0026, but will start
Fixes and fail-safe behavior in user rules apply.

## User-side policy routing example

The following example only shows how a user consumes a set; Tinect does not create these rules:

```nft
table inet router_policy {
    set tinect_healthy_v4 {
        type ipv4_addr
        flags interval
    }

    chain prerouting_mark {
        type filter hook prerouting priority mangle; policy accept;
        ip daddr @tinect_healthy_v4 meta mark set 100
    }

    chain output_mark {
        type route hook output priority mangle; policy accept;
        ip daddr @tinect_healthy_v4 meta mark set 100
    }
}
```

Then configured by the user:

```text
ip rule add fwmark 100 lookup 100
ip route add <healthy-overlay-route> dev tinect0 table 100
```

Use `prerouting` rules for forwarded traffic and `output` rules for traffic generated locally.
Adapt the mark mask, conntrack behavior, IPv6 handling, and rule priorities to the host. Tinect only
maintains the set; it does not assume a particular mark, routing table, TUN name, or default route.

When no egress candidate is healthy, its prefix is absent from the set. User nftables rules
therefore do not mark matching packets, and those packets do not enter Tinect through policy routing
or TUN. When an egress becomes healthy and its route binding is published as healthy, the prefix is
added to the set again, allowing new matching packets to enter Tinect.

## Remove the local fallback implementation

Implementations of this RFC must remove the local raw-IP fallback completely; it must not remain
as an undocumented compatibility path:

- Remove `local_route_fallback` and `local_route_fallback_if`, including validation, defaults,
  dry-run output, and runtime state.
- Remove `LocalRouteFallback`, Linux/macOS raw-IP sending, `IPPROTO_RAW`/`IP_HDRINCL`,
  `IP_TRANSPARENT`/`IP_FREEBIND`, interface binding, source-address rewriting, checksum
  recalculation, and the fallback send worker.
- Remove NAT rules used only by local fallback. Keep remote-egress NAT and the TUN INPUT firewall.
- Replace fallback-specific tests, configuration examples, and user documentation with nftables-set
  documentation.
- Remove dataplane branches for fallback candidates so the dataplane handles only packets that
  nftables or policy routing has sent to TUN.
- Do not retain a compatibility path for local raw-IP fallback after migration.

If the administrator still sends traffic to TUN without a healthy Tinect binding, Tinect must
reject or count it according to its existing no-healthy-candidate behavior. It must not attempt a
local raw-IP send.

## Security Impact

### Benefits

- Tinect no longer sends unauthorized/unprocessed packets from the local raw socket to the external network.
- Tinect no longer rewrites packet source addresses, forges native egress source addresses, or assumes normal socket backhaul NAT.
- nft rules, marks and policy routing are all explicitly configured by the administrator, Tinect only provides health status data.
- The set only contains the prefix of the current healthy route snapshot, and does not include any unverified addresses delivered by the remote end.

### Risks and constraints

- nft set is a routing signal, not a security boundary. Local users with nft administrative rights can modify set,
mark or ip rule; Tinect should not use set hits as the basis for ACL authorization.
- When the set update fails or the daemon is stopped, the administrator's nft rules may temporarily not be able to see the health prefix, causing
Fail-closed Tinect bypass; this is acceptable and safer default behavior than sending unhealthy traffic into the TUN.
- There may be a temporary stale positive during the set update lag period: the packet is sent to TUN and has no healthy binding
Rejected by Tinect. The implementation should try to submit the health status first before triggering the set deletion, and provide an update failure indicator.
But data plane health checks should not be relaxed to eliminate short windows.
- Tinect must reject sets that do not match the type, family or interval, and cannot clear or rebuild the user's existing sets.

## Compatibility and Migration

This is an intentional incompatible configuration and behavior change. Migration steps:

1. User creates a policy rule `inet` nft chain (optional); Tinect will create missing ones as needed `inet`
table and set.
2. Fill in the Tinect configuration `nft_healthy_set.prefix`, or fill in by address family
   `nft_healthy_set.v4`/`nft_healthy_set.v6`, set the destroy switch as needed.
3. The user adds the set of prerouting/output and hits the mark rule, confirming the mark mask, ip rule and
TUN/table routing order is correct.
4. Delete the configuration `local_route_fallback` and `local_route_fallback_if`.
5. First verify that the link status is consistent with the current Link/Circuit in scenarios of reconnection, delayed closure of old connections, and detection failure.
The status is consistent; the health set must not be enabled when the pre-repair fails.
6. Update daemon; confirm the set element and `tinect status/routes` The healthy candidates in are consistent.
7. Before stopping the old fallback, first confirm that there are no business paths that depend on the raw-IP fallback to work;
The new mode will not provide native egress for packets without health exports.

During an upgrade, the old and new daemons should not be allowed to manage the same TUN/set at the same time. Stop the old daemon first and confirm
The old fallback NAT and raw-IP resources have been cleaned up before starting the new daemon. User-owned nft table, chain,
rule, ip rule and routing tables are not automatically migrated by Tinect.

## Layered implementation

- `config`: Parse and verify `nft_healthy_set` of three address fields and two destroy switches, including strictly
of `table:name` Format, explicit naming precedence, derived names, Linux-only constraints, and legacy fallback field rejections.
- `routing`/`topology`: Calculate the healthy prefix set normalized by address family from the existing route snapshot;
No nft I/O is performed directly.
- `runtime`: Holds the current healthy candidate reference count, pending incremental events, committed set state,
lifecycle state, update failed, and degraded state.
- `platform`: Executed over existing Linux nft netlink boundaries `inet` Query/on-demand creation of table, and set
Query, create, incremental element update, and cleanup by configuration switch; must not be started `nft` Child process; do not execute mark,
ip rule or user policy routing.
- `dataplane`: Delete the raw-IP fallback branch and only process the overlay that has been sent to TUN by the system routing
packet.

## Testing and Acceptance Criteria

### Configuration and model testing

- accept legal `nft_healthy_set.prefix`,`nft_healthy_set.v4`,
  `nft_healthy_set.v6`;reject missing unique `:`, empty table/name, extra colon, illegal nft identifier,
Derived name is illegal and identical `table:name` Both as a v4/v6 target and non-Linux configuration.
- Verify prefix generated `<prefix>_v4`/`<prefix>_v6`, and verify that explicit v4/v6 configuration respectively overrides the corresponding
Address family; explicit configuration malformation must be rejected even if overridden.
- reject `local_route_fallback`,`local_route_fallback_if` Mixed with new fields or appear alone.
- Health set test coverage: no candidate, one healthy candidate, multiple candidates partially healthy, all failed, restored,
Multiple candidates for the same prefix, overlapping prefixes, IPv4/IPv6 separation and path override.
- Verify that membership of the set is not affected by route priority and is determined only by "at least one healthy candidate".
- Event-driven incremental testing coverage:`0 -> 1` Only add,`1 -> 0` Only delete,`1 -> 2` and `2 -> 1`
Do not operate set, duplicate/out-of-order events are idempotent, and irrelevant prefix events do not trigger full recalculation.

### nft platform test

- Create sets with correct type and interval flag in non-existing tables and empty tables; verify both destroy switches
The default value and exit destruction behavior do not distinguish whether the object was originally created by Tinect.
- A set of the correct type already exists and can be reused; reject and keep user if type, address family or interval does not match
The object remains unchanged.
- Lifecycle tests for creating a set, deleting a set, retaining a referenced set, clearing old elements on startup, and clearing elements on exit.
- A single netlink batch simultaneously deletes old elements and adds new ones; verify that the old set remains when injecting ACK/error
unchanged and can be retried.
- Recovery/behavior testing of external set removal, table removal, external type replacement, and duplicate daemon configurations.
- Verify that Tinect does not create or modify user chain/rule, mark, ip rule and routing tables.
- Static checks and runtime tests confirm daemon does not start `nft` Child process; all nft operations go through netlink
Finish.

### Linux namespace integration testing

Create user nft table, mark rule, ip rule, policy routing table and two available/unavailable
Use Tinect route candidate, verify:

1. When at least one healthy candidate, the target prefix appears in the set, the hit packet carries the expected mark and enters TUN.
2. When all candidates expire, the target prefix is   deleted from the set, and the packet no longer enters TUN, but is removed from the test namespace.
Normal default route leaves.
3. When multiple candidates change from one health to another, the set element remains present and will not be temporarily deleted and then added.
4. `/0` Address membership is correct when overlapping with more specific prefixes.
5. Elements are cleaned up when the daemon starts and exits normally; the set referenced by the user rule is not deleted, and the user rule/table
Unchanged; whether set/table is deleted is controlled by the destroy switch respectively.
6. After repeatedly restarting and simulating set deletion, the set can be re-created and eventually converge.
7. Event-driven changes to a single candidate health status only update the affected prefix; a batch will not clear or rebuild the entire set.
8. Compare the user ip rule, policy routing table, default route and user nft rule before and after the test to confirm that Tinect only
Modify the agreed set object.
9. When there is no healthy candidate, no raw socket, IPPROTO_RAW, source address rewrite or Tinect native occurs
NAT behavior.
10. When the old and new Link instances are reconnected and delayed close/error events are interleaved, the link healthy in status will not be
Overwritten by the old instance; status, route candidate health status, and set are eventually consistent.

### Quality Access Control

Implementation must pass `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`,`cargo test`;Modify Nix
After packaging or dependency, you still need to pass `nix flake check`. Real network testing must verify temporary namespace, TUN,
Routes, policy rules and nft sets are cleaned up on the exit path.

## Open issues

1. You need to confirm whether the nft kernel/library version allows interval set and element timeout to be used at the same time;
If supported, timeout can be used as automatic fail-closed protection after a daemon crashes.
2. It is necessary to determine the status/metrics field name when the set update fails, and whether the degraded state should
Affects daemon overall health.

## Implementation record

- `config` Implemented strict `table:name` parsing, address family derivation, explicit overrides, conflict checking, and
Linux-only checksum; old `local_route_fallback` Field rejected by unknown field error.
- `routing` implements an idempotent healthy-reference reducer keyed by `(prefix, candidate)`. The dataplane no longer provides raw-IP fallback; RFC-0032 and RFC-0033 define the semantics of explicit direct routes and final fallback.
- Linux `platform` Queries, on-demand creation and incremental updates via libnftnl/libmnl netlink `inet`
interval set; CIDR is encoded with an exclusive upper bound, deletion and addition are submitted in the same batch, and retained in case of failure
committed snapshot for retry.
- Link health status is bound to the instance generation, status, route snapshot and health set use the current
Link/Circuit ownership; delayed shutdown events for old instances are discarded.
- `cargo fmt --check`,`cargo clippy --all-targets --all-features -- -D warnings` and
  `cargo test` Passed; required for Linux namespace acceptance `CAP_NET_ADMIN` environment before executing.
