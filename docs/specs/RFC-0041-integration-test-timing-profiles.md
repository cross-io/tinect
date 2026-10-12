# RFC-0041: integration-test-timing-profiles

- Status: Implemented
- Created: 2026-08-23
- Last updated: 2026-08-27

## Background and Problem

Tinect's control plane and data plane contain multiple independent time status machines. The
production circuit lease is twelve hours, and the source sends a signature renewal every thirty
seconds; QUICP established session idle, return-flow TTL, CircuitBroken feedback deduplication, and
bare UDP/QUICP PMTU recovery reexploration also have minute or hour-level periods respectively.

Existing privileged integration tests reduce fault injection by tightening configurable link
keepalive, idle timeout, and path migration times, but compile-time protocol constants cannot be
adjusted. This leads to two types of problems:

1. Although the test spans the lease-refresh throttle, it does not span the twelve-hour lease;
   even if the refresh completely fails, the test may still pass.
2. To observe renewal or PMTU recovery, CI needs to realistically wait tens of seconds; longer
   final fallback paths simply cannot be performed in process-level testing.

Simply applying the same multiplier to all Durations is unsafe. The triggering of error status,
immediate feedback, cycle renewal, lease expiry, and reconnection belong to independent recovery
channels; shortening them together may allow later recovery to cover up earlier error status, and
may also incorrectly shorten I/O deadlines such as DNS, management interface, or shutdown that are
only used to prevent stucks.

Static analysis also found that circuit binding and indexed deadline heap hold locks respectively:
refresh first updates the binding and then updates the heap, and expiry pops the heap first and then
removes the binding. When interleaved with CLOSE and Link teardown, it may leave an orphan deadline
without binding, or allow legitimate operations to briefly observe that the binding does not exist.
Time compression will significantly increase the observable probability of this race condition.

## Target

- Let privileged integration tests explicitly select short cycle time configurations without
  changing production default times.
- Disable arbitrary global scaling and use a small number of named, reviewable, and verifiable
  invariant profiles.
- Separate protocol life cycle, maintenance/recovery and topology time domains; I/O anti-stuck
  deadline does not scale by default.
- Make circuit binding, lease deadline, generation refresh, shutdown, link cleanup and expiry
  atomic.
- At the same time, a small amount of production time sentinel is retained to prevent short-cycle
  profiles from becoming the only evidence.
- Binaries without the testing feature enabled must completely ignore the testing profile
  environment variable.

## Non-goals

- Do not expose test time as user configuration or stable CLI interface.
- No changes to wire format, signed input, counters, TTL encoding, or inter-node compatibility.
- Do not use Tokio paused time to drive multi-process namespace testing; QUIC, kernel network
  timers and external commands still use real time.
- Do not scale DNS, management, control send, shutdown, and test harness total timeouts.

## the term

- **Production profile**: The default configuration of the existing production time is fixed.
- **Named test profile**: An explicit set of Durations selectable only under the test feature.
- **Behavior Time**: The time when the protocol or maintenance status machine decides when to
  change the status.
- **Observation time**: The maximum wall clock time the shell harness waits for state to appear;
  it is not the semantics of the protocol under test.

## design

### Building and selecting boundaries

Added Cargo feature `integration-test-timing`. The process reads `TINECT_TEST_TIMING_PROFILE` only
when the feature is enabled; production is always selected when the feature is not enabled. The test
environment must output non-production profile names in the boot log to facilitate diagnosis of
incorrect builds or missing environment variable passes.

The environment variable only accepts the following names and does not parse Duration, JSON or
times:

- `production`: original production time;
- `circuit-fast`: shorten lease, renew and traffic refresh throttle;
- `maintenance-fast`: shorten QUICP session, return-flow, no-session deduplication and bare
  carrier PMTU rise re-exploration;
- `topology-fast`: Shorten LSA TTL and snapshot recovery period.

Unknown names must fail before the daemon can execute the command. After profile is initialized, it
cannot be changed within the process.

### Time domains and invariants

profile must be explicitly verified:

- `circuit_renew_interval < circuit_lease`;
- `lease_refresh_throttle < circuit_lease`;
- topology TTL allows at least one positive integer second keepalive; configuration checksum
  requires `keepalive_secs < topology TTL`.

Link keepalive, idle timeout, reconnect and path migration still use the node configuration and
perform the original verification. The polling interval, ping timeout, and CI job timeout of the
test harness do not follow the profile scaling.

The lease of `circuit-fast` must cover at least multiple renewal cycles; the test needs to check the
intermediate state before the lease and the final state after the lease at the same time, and
cannot only check the results once after all recovery mechanisms are run.

### Circuit binding Atom state

Each Router uses a single sync state to simultaneously have:

- `(incoming Link instance, CircuitId) -> CircuitBinding`;
- A unique indexed lease deadline for each live binding.

The following operations must complete binding and deadline changes within the same writer critical
section:

- OPEN installs binding and initial deadline;
- DATA/renewal refreshes deadline and generation;
- authenticated CLOSE;
- relay OPEN abort;
- incoming/outgoing Link teardown;
- expiry Conditional deletion of the current generation.

refresh must recheck the throttle after obtaining the writer lock to avoid multiple concurrent data
packets from repeatedly increasing the generation based on the same old read value. Asynchronous
authorization/session/label cleanup is executed after atomic removal of binding, and cannot be
awaited while holding a synchronous state lock.

expiry must not temporarily delete the current binding in order to check generation. When the
deadline generation does not match, only the current deadline is restored within the same state
lock; once CLOSE or Link teardown returns, the old refresh must not re-insert the orphan deadline or
binding.

## Protocols, data formats and security implications

The wire protocol, authentication field, and signature input are unchanged. All values   for the
production profile remain intact, so the running semantics of a normal build are unchanged.

Test features should not make it into production Nix/release builds. Even if you mistakenly build
with `--all-features`, you still need to also explicitly set the named environment variable to
enable short periods. The test profile only shortens the resource life cycle and does not relax ACL,
authentication, path verification, replay protection, sending budget or Link instance binding.

Atomic binding status strengthens the safety boundary: concurrent expiry, CLOSE, and link
replacement cannot revive a revoked lease, nor can it leave an orphan deadline that will be cleared
in the future.

## Compatibility and migration

No configuration or wire migration required. Production builds do not enable the feature; CI builds
the network test binary with the feature separately. Normal unit tests still use the production
profile when environment variables are not set.

## Testing and Acceptance

### Unit and model testing

- All named profiles pass lifecycle invariant verification, and any multiplication or unknown
  names are rejected;
- Deadline reset maintains one heap entry for each binding;
- Concurrent refresh rechecks the throttle in the writer lock and does not advance the generation
  repeatedly;
- The current generation is exactly expiry, and the expired generation does not remove the current
  binding;
- CLOSE, abort, and Link teardown remove binding and deadline at the same time, leaving no orphan
  entry;
- Environment variables cannot change the production profile when the feature is not enabled.

### Privileged integration testing

- Under `circuit-fast`, renewal continuity spans multiple renewal cycles and does not rebuild the
  circuit;
- active lease continuity spans the entire short lease, continuous business is available and the
  active identity does not change;
- relay control congestion across renewal, and bounded convergence after admission back pressure
  and link replacement;
- After the PMTU is reduced under `maintenance-fast`, it is restored in place through the
  shortened upward reprobe without rebuilding the circuit;
- Under `topology-fast`, across multiple LSA TTL/refresh cycles, paths with unchanged semantics
  will not generate OPEN storms;
- The production profile continues to run at least one real renewal/idle/PMTU sentinel;
- Direct path, multi-hop, downstream restart, link replacement, loss of control/congestion,
  duplicate or late feedback continue to be covered by the existing fault injection matrix; the
  OPEN candidate fallback script for RFC-0038 must actually be included in CI.

After all tests are completed, confirm that namespace, TUN, routing, qdisc, firewall rules and
daemon processes have been cleaned up.

## Open Questions

- The explicit Clock trait and Tokio paused time can be introduced later for pure actor/component
  testing; it is not a replacement for multi-process real network testing.
- Return-flow and QUICP established expiry are currently mainly covered by unit tests. Independent
  and smaller namespace scenarios can be added in the future without applying all profiles to the
  entire matrix at the same time.

## Implementation Notes

2026-08-23: Implement `integration-test-timing` feature,
production/circuit-fast/maintenance-fast/topology-fast naming profile and startup log verification;
merge circuit binding and indexed deadline heap into atomic status, and recheck refresh throttle in
writer lock. CI selects the corresponding profile for renewal, PMTU, topology and control congestion
scenarios, while retaining the production renewal sentinel and filling in the previously missed
`remote_open_candidate_fallback.sh`.

In Linux CI, two sets of workspace release unit tests, production and all-features, production and
all-features strict Clippy, rustfmt, ShellCheck, and the following privileged scenarios:

- circuit-fast renewal continuity;
- circuit-fast active lease continuity;
- circuit-fast relay control congestion;
- maintenance-fast RFC-0022 dynamic budget/PMTU recovery;
- topology-fast four-node reconnect/path switch;
- production OPEN candidate fallback;
- production 90-second renewal sentinel.

After testing, confirm that the corresponding namespace and daemon processes have been cleaned up.
The final GitHub Actions acceptance record is kept by the implementation PR.
