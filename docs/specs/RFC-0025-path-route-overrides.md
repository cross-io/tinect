# RFC-0025: Path-level routing overlay

- Number: RFC-0025
- Status: Implemented
- Created: 2026-08-05
- Last updated: 2026-08-05

## Background and Problem

The global route priority cannot express the scenario of "the same exit uses different priorities on
different paths", nor can it temporarily disable or add the route of the exit on a certain path. The
manual path originally used the top-level `paths.<destination>`, and the configuration structure
also required an additional key to express the destination.

## Goals and Non-goals

Target:

- Move manual path to `peers.<destination>.paths`;
- Add local `override_routes` to the path;
- Support absolute priority, priority delta, disabled and new `ip_cidr`, `domain` or `site_set`
  selectors;
- Maintain per-packet route matching without configuration resolution and temporary allocation.

Non-goals:

- Does not change Circuit, Physical or encrypted wire formats;
- Do not send override to relay;
- Does not change relay's authorization semantics for path suffixes.

## Terminology and Constraints

- "Global route" refers to the peer candidate declared in `peers.<name>.routes`, not the same
  prefix candidate for all peers.
- "Wildcard override" refers to an override that omits the selector; it only acts on routes
  declared by the peer and does not create routes out of thin air.
- "Active path" refers to the path that is currently committed and still used by Circuit, not the
  preferred path in the configuration.

Selectors cannot be specified repeatedly in the same path, and wildcard and precise selector
coverage cannot be mixed. Coverage with selector can only use absolute `priority`; when the global
route of the peer is not matched, a positive priority creates a new candidate for the peer, and a
priority of zero does not create a candidate.

## Configuration format and semantics

```yaml
peers:
  exit:
    routes:
      - {ip_cidr: 10.0.0.0/8, priority: 100}
    paths:
      - path: [source, relay, exit]
        override_routes:
          - {ip_cidr: 10.0.0.0/8, priority: 0}
          - {ip_cidr: 192.0.2.0/24, priority: 80}
```

Each override must specify `priority` or `priority_delta` only. Override with selector must use
priority; the selector strictly matches the route declared by the peer itself according to the
canonical SiteSet. If there is no match, use priority to add a candidate for the peer. When no
selector is written, all declared routes that apply to the peer. If priority is zero, or the
delta-adjusted result is less than or equal to zero, the candidate will be removed. wildcard and
selector-specific override must not appear at the same time.

Overrides only apply to the currently active manual path of the source node. During route migration,
the old circuit and its overrides continue to take effect; the effective route snapshot is switched
after the new circuit is submitted. Automatic paths have no path-level overrides.

The IP route is first selected according to the longest `ip_cidr`, and the domain name route is
based on canonical SiteSet; then the final priority is selected in the health candidate. Candidates
for the same selector from different peers are still merged; exact coverage by one peer does not
modify the candidates of other peers.

## Implementation and performance

The configuration layer retains global routes, finds the corresponding peer path according to the
active Circuit at runtime, and generates an immutable `RouteSnapshot` containing valid imports and
secure bindings. Each available candidate for each prefix retains its own binding; you cannot retain
just one candidate because of build order, otherwise priority selection might select an egress
without a binding. The data plane worker only reads the current snapshot for each packet; the
health cache is reused, and the coverage calculation is only performed when the route refresh or
configuration/active circuit changes.

Health state is cached by the `(prefix, candidate)` dimension instead of only by candidate nodes. A
node that has a binding on a `/32` shall not cause it to be considered a healthy candidate for `/0`
in the absence of a `/0` binding. This index reuses existing string keys under stable snapshots and
does not enter per-packet configuration parsing or temporary allocation paths.

override-only `ip_cidr` will be added to the prefix collection of managed route. When the path is
hot loaded, the daemon adds or deletes the corresponding TUN route in the platform layer, and cleans
the currently owned collection when exiting. All system I/O still occurs only at platform
boundaries.

`wire_paths` only exports the path list composed of node identities, and override does not enter the
control plane or data plane wire payload.

The refresh task maintains a local overlay cache of old active paths. When configuration hot
reloading removes the old path but the old circuit has not yet completed migration, the cache
continues to serve its override; after the active circuit switches to the new path, the cache is
updated or discarded. This cache does not participate in network protocols.

## Design Tradeoffs and Deployment Impact

Route imports and secure bindings are put into the same immutable snapshot to ensure atomic
switching between priority and actual sendable bindings; the cost is that each route, circuit or
configuration change must rebuild the route table in the refresh task. This overhead does not enter
the packet processing path. override-only `ip_cidr` will be included in the system route set
maintained by the daemon itself. During hot reloading, the prefixes that are no longer needed are
deleted first, and then the new prefix is   installed. When `managed_routes: false` is used,
external policy routing is still responsible for sending it into the TUN.

This is an intentionally incompatible configuration change: you must change the top-level
`paths.<node>` to `peers.<node>.paths[]` when deploying, and change the path array to an object with
a `path` field. Old formats are not silently converted.

## Security and Compatibility

Override is a local route-selection policy that does not grant new relay permissions, does not
bypass `EgressPolicy::authorize()`, and does not cause the relay to decrypt the end-to-end payload.
The old top-level `paths` is incompatible with the old path array writing method and will be
rejected when it appears in the configuration.

## Testing and Acceptance

- Configuration verification covers peer-level paths, duplicate coverage, priority/delta conflicts
  and delta-only new prefix;
- Routing unit tests cover exact coverage, wildcard, disabled, new, delta and longest prefix;
- The routing unit test covers the health isolation of the same node across prefix bindings, and
  the priority selection of multiple candidate bindings for the same prefix;
- Circuit testing confirms that the wire path does not contain override;
- Data plane and platform testing cover snapshot replacement, managed route additions and
  deletions, and exit cleanup;
- Through `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` and
  `cargo test`.

## Open Questions

Currently only absolute priority and priority_delta are supported; no per-path ACL override or
cross-peer batch override syntax has been introduced.
