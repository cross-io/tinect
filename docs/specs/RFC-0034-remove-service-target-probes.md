# RFC-0034: Remove native service target detection

- Number: RFC-0034
- Title: Remove native service target detection
- Status: Implemented
- Created: 2026-08-13
- Last updated: 2026-08-27

> RFC-0046 unifies the CircuitNoSession feedback described in this article into CircuitBroken; the
  remaining boundaries regarding Circuit lease and Link life cycles remain unchanged.

## Background and Problem

The existing `health_checks.<peer>.targets` has a TCP connection directly initiated by the source
node to `HOST:PORT`, but the detection traffic is not bound to the specified peer, circuit or path.
Therefore, successful detection can only prove that the system route currently selected by the
source node can access the target, but cannot prove that the NAT, public network route or multi-hop
path of the specified exit is available. When system routing is switched to direct or backup egress,
detection results may also come from the wrong egress.

After a threshold of probe failures is reached, the existing implementation shuts down the entire
physical link registered with that name. This not only requires that the detected node happens to be
a direct peer, but also cancels other circuits sharing the link. The fault domain is not consistent
with the detected service. Continuing to expose this configuration could easily lead an operator to
believe that it provides path or exit-level health checks.

Tinect has maintained the health status of physical Link, topology path, Circuit and data plane
binding respectively: authentication keepalive and idle timeout are responsible for adjacent links,
signature LSA TTL and capacity proof are responsible for multi-hop topology, OPEN/RENEW,
`CircuitBroken` and lease are responsible for Circuit, and sending results are responsible for
current data plane binding. Therefore, removing service probes without path ownership should not
weaken these existing convergence mechanisms.

## Goals and Non-goals

Target:

- Remove `health_checks`, `targets` and the source node TCP probe worker.
- Reserve and remain public `link_health.keepalive_secs`, `idle_timeout_secs` and
  `reconnect_interval_secs`.
- Preserve peer `healthy` state, Circuit `healthy` state, route candidate health selection,
  `nft_healthy_set`, and Prometheus health indicators.
- Let old configurations explicitly fail verification to avoid silently ignoring expired detection
  intentions.

Non-goals:

- Do not add ICMP, TCP, or HTTP probe protocols sent through the specified Circuit.
- Does not change the wire format of Link, Circuit, topology or data frame.
- Does not change path priority, migration stability window, or direct fallback semantics.
- Does not remove common peer endpoint DNS resolution capabilities.

## the term

- Service Target Probe: Legacy behavior of source node connecting directly to
  `health_checks.*.targets`.
- Link Health: The current health status of the adjacent authentication physical connection.
- Binding health: Whether a certain export circuit binding available for data plane selection is
  available.

## design

Delete the top-level `health_checks` configuration field and its `HealthCheck` type. Since `Config`
uses `deny_unknown_fields`, configurations that still carry this field will be explicitly rejected
by `tinect check` and `tinect up`; the operator must delete the entire configuration block before
starting a new version of the daemon.

Remove the TCP probe worker, threshold/hold-down status machine, and health registry that only saves
probe results across reconnections. A newly established Link contributes to control-plane health after it has
completed authentication and registration. The health status participates in the control plane; thereafter the
status changes are still driven by the following events:

1. QUIC/Physical keepalive, authentication payload idle timeout and connection closure are
   responsible for neighboring peers;
2. After the initial topology Snapshot two-way synchronization is completed, Link can be used for
   topology pathfinding;
3. Expiration of the signed LSA or disappearance of the edge will revoke the corresponding path
   proof;
4. Circuit OPEN/ACK and RENEW/ACK every 30 seconds prove that the entire multi-hop Circuit still
   exists;
5. `CircuitBroken`, Link replacement and lease expiry revoke stale state;
6. DATAGRAM send errors other than backpressure update Link/binding health and trigger reselection.

`status.links[].healthy`, `status.circuits[].healthy`, `tinect_links_healthy`,
`tinect_circuits_healthy` and data plane route snapshot are retained. Linux `nft_healthy_set`
continues to maintain overlay binding and explicit direct route based on current health and does not
rely on removed service probes.

The DNS resolver continues resolving peer endpoints and collecting underlay addresses; only TCP
connect helpers that have no other callers are removed. The parsing order, cache and system fallback
of `dns_servers` remain unchanged.

## Protocols and data formats

There are no changes to the wire protocol, encryption, authentication, ACL, and forwarded frames.
Configuration data format removal:

```yaml
health_checks:
  exit:
    targets: ["1.1.1.1:443"]
    interval_secs: 2
    fail_after: 3
    recover_after: 5
    hold_down_secs: 15
```

`link_health` remains unchanged:

```yaml
link_health:
  keepalive_secs: 10
  idle_timeout_secs: 35
  reconnect_interval_secs: 2
```

## Security and Compatibility impact

Removing the local TCP probe avoids incorrectly attributing the success of other local exits to the
specified peer, and also prevents an external TCP service failure from closing the shared link
carrying multiple circuits. Peer authentication, end-to-end payload encryption, egress ACLs, and
relay undecryptable invariants remain unchanged.

This is an intentional configuration incompatible change. Old configurations are not silently
downgraded; explicit denial prevents operators from mistakenly believing that egress services are
still protected by probes. When deploying, you should first delete `health_checks` from all node
configurations and then upgrade the daemon.

## Testing and Acceptance

- Configure single test to verify that normal configuration and `link_health` default
  value/illegal value still work according to the original semantics.
- Configure single test to verify that the old `health_checks` field was explicitly rejected.
- Unit tests continue to cover Link, topology, Circuit, binding and route healthy state changes.
- Remove the privileged network test and CI matrix items that only verify TCP targets, thresholds,
  and hold-down.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` and `cargo
  test`.
- Run the Link/path/Circuit fault injection scenario on the network integration CI, covering at
  least the direct path, multi-hop relay, downstream restart or Link replacement, control feedback
  and lease renewal convergence, and confirm that network resources are completely cleared.

## Migration and deployment

Delete the entire `health_checks` block for each node before upgrading. Reserve `link_health`; if
the deployment has relied on public network service target detection, it should be monitored
externally for alarms, or wait for a detection protocol with clear circuit/path ownership in the
future. Ordinary host TCP connection simulation cannot be used.

## Open Questions

If egress service detection is added in the future, the destination, circuit and return
authentication bound to the detection request must be clearly stated in the protocol, and
bounded convergence must be proven in the event of path switching, feedback loss, duplication,
disorder and downstream restart. This RFC does not reserve compatibility fields.

## Implementation Notes

2026-08-13 Implementation completed: delete `health_checks` configuration, TCP probe worker,
threshold state machine and probe registry; retain `link_health`, Link/Circuit/binding healthy
State, management interface, Prometheus indicator and `nft_healthy_set`. Old configurations are
explicitly rejected by unknown-field validation.

Passed `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` and `cargo
test` (205 library tests, 26 binary tests). The release build of Network Integration CI passes:

- `tests/remote_reconnect_path_switch.sh`
- `tests/remote_circuit_feedback.sh`
- `tests/remote_renewal_continuity.sh`

The test covers direct/multi-hop switching, short-term and long-term relay failures, downstream
process restart and Link replacement, repeated/late feedback, unknown session feedback and
continuous forwarding across RENEW cycles, and confirms that network resources have been cleared.
