# RFC-0044: Underlay host routing ownership and transaction lifecycle

- Number: RFC-0044
- Title: owned-underlay-route-lifecycle
- Status: Implemented
- Created: 2026-08-24
- Last updated: 2026-08-24

## Background and Problem

When `managed_routes` is enabled, Tinect will pin the peer endpoint to the current underlay default
gateway before installing an overlay prefix that may override the default route. Previously, these
precise host routes were not in the daemon's resource ledger: normal exits, failed startups, and
subsequent rollbacks only deleted the overlay prefix pointing to TUN, so the host routes would be
left behind permanently. Linux installation also uses `replace`, which may overwrite the same
destination host route configured by the administrator, and cannot restore the original value when
exiting.

This not only violates "only clean up resources created by Tinect when stopping", but may also
change the host's real underlay routing after upgrades, relocations, or repeated starts.

## Target

- Only create precise host routes for peer endpoints that do not yet exist in the current main
  routing table;
- Returns an unforgeable ownership token for each actually created underlay route and is held by
  the daemon life cycle;
- When exiting normally, first delete the overlay prefix, and then delete the underlay route in
  the token accurately;
- When any step of the installation fails, the overlay and underlay routes created by this call
  will be rolled back in reverse order;
- When changing prefixes during runtime, first add new items and then delete old items; when
  deletion fails, undo the new items and retain the old logical snapshot;
- Do not repeatedly acquire or discard underlay ownership when dynamically synchronizing the
  overlay prefix;
- Retain `managed_routes: false`'s semantics of not manipulating the routing table at all.

## Non-goals

- No changes to configuration format, route priority, policy routing, or table selection;
- Do not take over, repair, or delete precise host routes that existed before the daemon was
  started;
- No longer guessing after a crash whether old routes without ledgers were created by historical
  Tinect processes;
- No changes to circuits, control protocols, encryption, or ACLs.

## design

The platform installation interface returns `UnderlayRouteOwnership`. This type hides routing
details and can only be returned to the platform cleanup interface to prevent the caller from
rebuilding a deletion list that may have changed based on the current configuration.

Linux reads the main table before writing: skip the endpoint if `/32` or `/128` of the same address
family already exists; use add instead of replace for new routes, and record the endpoint, gateway
and output interface. macOS continues the system `route` interface, but only writes successful add
entries to the token. When any subsequent add fails, the platform layer deletes the entries
successfully created by this call in reverse order before returning an error.

The daemon's `NetworkResources` holds the token. The shutdown sequence is: stop the worker, delete
the dynamic overlay prefix pointing to TUN, and then release the underlay token; therefore, as long
as the overlay default route still exists, the carrier endpoint always has an escape route. When
prefixes are added or deleted during runtime, an empty underlay collection is passed in, and only
the original overlay ownership ledger is updated.

## Security and Compatibility

The protocol and data format remain unchanged. The existing administrator host routing has been
changed from "may be overwritten" to always reserved, which is a security tightening. Routes left
over from historical crashes will not be automatically deleted to avoid misjudgment of system
statuses from unknown sources as their own resources; the operator can manually clean them after
confirmation. Normal configuration does not require migration.

## Testing and Acceptance

- Rust fully formatted, Clippy and unit tests passed;
- In the Linux privileged namespace scenario, preset the administrator's precise host route, and
  then start the daemon containing the overlay prefix and two endpoints; verify that the preset
  route has not been replaced and the missing route has been created;
- After sending TERM to the daemon, verify that the overlay prefix and the host route created by
  Tinect disappear, while the administrator route maintains the original gateway/metric; the
  fixture finally cleans up the namespace, TUN, socket and process.

## Open Questions

none. If cross-process crash recovery needs to be implemented in the future, a durable resource
ledger with instance identity should be used, and ownership cannot be inferred solely from the
routing shape.
