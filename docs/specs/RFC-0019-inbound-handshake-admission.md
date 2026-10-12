# RFC-0019: Inbound handshake admission

- Number: RFC-0019
- Status: Implemented
- Created: 2026-07-31
- Last updated: 2026-07-31

## Background and Problem

The inbound QUIC receive loop is serial until the transport handshake and identity flow are
completed. Network scanning, invalid NAT state, or a half-open connection at the opposite end can
make a handshake wait for the complete transport idle timeout, blocking subsequent legitimate peer
access. When legacy connections occur on public network endpoints, this can further delay topology
synchronization and trigger link recovery budget exhaustion.

## Target

- Limit the time a single inbound handshake takes up the accept loop.
- Let the timeout connection be discarded before continuing to receive subsequent connections.
- Keep authenticated connections, identity verification, and duplicate link convergence semantics
  unchanged.

## Non-goals

- Does not change the QUIC wire protocol, authentication, or topology message format.
- Do not turn unknown peers into peers that allow connections.

## design

The main inbound accept loop has a fixed 10 second timeout for `accept_with_bare` packets. After
timeout, only the current unauthenticated connection is canceled and the loop continues; normal
errors are still recorded according to the existing classification, and endpoint closing is still
the termination condition. The Link life cycle after authentication is completed is not affected by
this timeout.

## Security and Compatibility

Timeout reduces the resource usage of legitimate connections by unauthenticated connections, and
unknown peers will still be rejected. Extreme paths with handshake RTT exceeding 10 seconds will
require redialing; existing QUIC retry and outbound reconnect mechanisms guarantee recovery. This
change does not change compatibility between authenticated nodes.

## Deployment and migration

It will take effect after upgrading the daemon, and there is no need to change the wire protocol.
When old conntrack state occurs in public network NAT, the deployment operation should first stop
the relevant daemon, clean up the corresponding UDP conntrack entries, and then start the node.

## Testing and Acceptance

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- Three-node public network path acceptance: adjacent links are all healthy, the active path
  reaches the exit through the relay, and continues to exceed the topology snapshot recovery
  window.

## Implementation Notes

- The inbound accept loop of `src/main.rs` uses a 10 second handshake timeout.
