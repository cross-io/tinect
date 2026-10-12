# RFC-0021: bounded migration after preferred path is ready

- Number: RFC-0021
- Status: Implemented
- Created: 2026-08-03
- Last updated: 2026-08-27

> RFC-0046 updates the Circuit control plane used by this RFC: Migrate to associate OpenAck with
  CircuitId and no longer use the path MTU in SessionAck, Open nonce or OPEN; the path priority,
  readiness, drain and conditional switching semantics of this RFC still apply.
## Background and Problem

Manual `peers.<destination>.paths` expresses priority in order. When the preferred relay is not
ready at startup, the circuit may first be established on the direct fallback; if reconcile only
checks that the current circuit is still in the candidate list, the relay will not be migrated again
after recovery, resulting in high latency, packet loss, and paths inconsistent with configured
priorities.

## Goals and Non-goals

The goal is to make the first ready candidate of each destination the only "preferred ready path"
and complete the migration within the bounded time after it becomes stably available; the old
circuit forwarding is retained during the migration, and the old lease, waiter, route and traffic
count are cleared after the migration is successful. The state interface must expose the migration
stage, target, and latest failure reason.

Non-goals: Does not change the wire frame, end-to-end encryption, ACL, OPEN/ACK authentication or
relay decryption boundaries; does not guarantee the delay or packet loss of the physical link
itself, only guarantees that the local path life cycle ultimately follows the priority.

## Terminology and Design

- **Preferred Ready Path**: Scanned in configured order (or autopath sorting), the first candidate
  with next hop Link authenticated and `topology_ready`, end-to-end path verifiable, and MTU
  available.
- **MigrationPending**: After the preferred path is stable and ready, the solo worker is waiting
  for/executing migration.
- **MigrationOverdue**: The migration deadline has expired and has not yet been completed; the old
  path is only used as a restricted safety fallback, continues to be bounded and retried, and
  cannot be silently marked as meeting the preferred policy.

Reconcile runs immediately when Link, topology or circuit generation changes, and checks every
second. The preferred path must be ready for 1 second continuously before migration is started; the
default deadline is 5 seconds, and the old circuit drain timeout is 1 second. Parameters are
controlled by the `path_migration` configuration block. The underlying circuit migration is not
equivalent to the data plane flow stickiness: each TUN packet will reselect the egress based on the
current healthy candidate, and the binding of the quintuple to the old egress will not be retained,
so the next packet can be switched back after the preferred egress is restored.

The migration worker first completes the RFC-0046 signature Open/OpenAck, session installation and
CircuitId binding in the preferred path. After success, atomically replace the active circuit
reference of destination, refresh the route, and then send CLOSE to the old Link; the old circuit
continues to carry traffic before switching. Each destination has only one worker, and generation
events will not generate duplicate OPENs.

## State interface

The `CircuitStatus` response adds `migration_state`, `preferred_path`, `migration_started_at` and
`migration_last_error` (and corresponding observable names). `active_path` will only be updated
after the new circuit is successfully installed. The above fields belong to the native Unix state
interface, not the network wire frame.

## Security and Compatibility

This RFC does not change network framing, encryption, or ACLs. Old nodes can continue to forward
circuits, but this RFC does not provide migration guarantees; all source nodes should be upgraded
first during deployment. The state interface field must match the same version of CLI/daemon.

## Testing and Acceptance

- Fallback is established first, relay is then ready, and is migrated to relay within the
  deadline;
- The preferred short jitter will not switch repeatedly; OPEN/OpenAck or session installation
  failure will not forge success;
- During the migration, the old path can be forwarded. After success, the old circuit will be
  closed and the solo worker will not be repeated;
- When the deadline expires, `MigrationOverdue` will be generated and bounded will continue to be
  tried again;
- Three-node acceptance covers relay disabling/restoration, migration without restarting at both
  ends, packet loss/delay, old status cleanup and policy routing outbound traffic, and cleans up
  TUN, routing, namespace, and firewall at the end.

## Open Questions

Real deployment should adjust the stability, deadline, and drain parameters based on operational
observations; the default values   favor fast convergence and avoid repeated OPEN of the same
destination through the ready window and solo migration workers.

## Implementation Notes

Implementation Notes (2026-08-03): Implemented `path_migration` configuration, first ready candidate
comparison, single destination stability/solo worker/deadline state, atomic active switching and
old circuit drain; supports path/migration parameter hot reloading to retain active circuit state,
migration failure log contains current/preferred path, start time and reason; `cargo fmt --check`,
strict clippy, 95 library tests and 16 main program tests passed. Fault injection test: Shut down
and restore the trunk, verify A↔C direct fallback and non-restart path migration; clean up the
namespace, TUN and test routing after the test is completed.

Implementation Notes (2026-08-13): After the migration drain expires, first snapshot the old Link
from the Link registry, and then perform bounded CLOSE sending; the network wait no longer holds the
registry lock, avoiding a slow control flow pause for concurrent Link registration and cleanup. The
Link registry also uses a synchronous mutex that only protects short HashMap critical sections, so
that if the supervised future brings guard across the network await again, it will fail at compile
time because `Send` is not satisfied.
