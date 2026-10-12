# RFC-0004: Routing snapshots and data plane metrics

- Number: RFC-0004
- Title: Routing Snapshot and Data Plane Indicators
- Status: Implemented
- Created: 2026-07-23
- Last updated: 2026-08-05

## Background and Goals

Each TUN packet before sending the path will read the route-import configuration and reconstruct the
candidate `Vec`. At the same time, there is a lack of TUN sending and receiving and routing
selection time-consuming indicators. The goal is to remove such allocations without changing routing
semantics, and to provide local data plane counters that can be compared against QUIC link metrics.

## design

`route_imports` is constructed as immutable `Arc<Vec<RouteImport>>` when the daemon starts, and the
sending path directly borrows this snapshot. The health status is still provided by the atomic value
of each `SecureRoute`. `routing::select_flow_action` selects candidates for each packet based on the
longest prefix, priority and current health status; the flow affinity of the five-tuple to the
egress is no longer maintained. Health changes do not require rebuilding the candidate set, and the
restored high-priority egress will take effect in the next packet.

`Observability` uses atomic counting to record the number of TUN packets/bytes sent and received,
the number of route lookups and the cumulative time taken. The state Prometheus endpoint exposes
these counts; existing circuit, ACL, QUIC, and forward queue metrics remain compatible.

## Security and Compatibility

Does not change any protocol framing, encryption, ACL or relay behavior. Metrics are only exposed
through the legacy local management interface and do not contain dynamic network labels or packet
content.

## acceptance

- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  passed.
- The transit traffic of the three nodes remains stable, and TUN and route counts can be seen from
  the state interface.
- The same quintuple switches to the backup egress when the primary egress is unavailable. After
  the primary egress is restored, the primary egress is reselected for the next packet.

## Implementation Notes

The implementation is located at `src/dataplane.rs`, `src/observability.rs`, `src/status.rs`. The
sending pipeline and background session status machine still require separate RFCs, which will be
implemented after relay binding readiness can be observed.
