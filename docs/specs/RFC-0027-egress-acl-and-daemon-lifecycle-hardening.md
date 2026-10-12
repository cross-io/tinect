# RFC-0027: Exit ACL and daemon life cycle hardening

- Number: RFC-0027
- Status: Implemented
- Created: 2026-08-09
- Last updated: 2026-08-10

## Background and Problem

`allowed_routes` controls egress forwarding out of the local TUN address, and `allowed_local_ports`
controls the protocol and port delivered to the local TUN address. The two are independent
authorization dimensions, but the runtime previously only installed the egress policy when
`allowed_routes` was configured, causing only nodes configured with `allowed_local_ports` to deliver
the decrypted payload directly to TUN.

The egress ACL makes decisions on each decrypted inner IP packet. For IPv4 non-first fragments and
IPv6 Fragment Header non-first fragments, the transport layer port is not in the current packet;
interpreting the beginning of the payload as a TCP/UDP port will cause the malicious source to forge
an allowed port value.

In addition, public key configuration parsing tolerates leading and trailing whitespace, while
handshakes and source mappings use raw string comparisons; duplicate public keys also allow a
network identity to be mapped to multiple local names. Although the daemon has a global supervisor,
some Link, TUN, and derived workers have not been added to its cancellation and join paths.

## Goals and Non-goals

Target:

- Install unified `EgressPolicy` on any node configured with `allowed_routes` or
  `allowed_local_ports`; native delivery is determined by port ACLs only, non-native destinations
  must still match route ACLs.
- Fail-closed for fragmented packets that cannot be safely read from TCP/UDP ports.
- Give the peer public key in the configuration a unique, canonical text representation.
- Have the daemon shut down and wait for all long-running TUN, Link, and spawn workers to exit
  before cleaning up network resources.
- Remove hot reload entries that are not used by deployment requirements so that running
  configurations remain immutable.

Non-goals:

- Does not implement IP fragment reassembly across DATAGRAM, nor change any wire frame,
  encryption, circuit or relay plaintext boundaries.
- Do not relax `allow_transit`, `allow_relay`, `EgressPolicy::authorize()` or host network
  ownership constraints.
- Does not preserve hot reload compatibility entries or partial update semantics.

## the term

- **Local delivery**: Packets whose inner IP destination address belongs to the current node
  `tun.addresses`.
- **Non-first fragment**: IPv4 fragment offset is non-zero, or IPv6 Fragment Header offset is
  non-zero.
- **Managed worker**: A long-term asynchronous task canceled and joined by `DaemonSupervisor` or
  its subtask group.

## design

### ACL installation and sharding

As long as either `allowed_routes` or `allowed_local_ports` is not empty, the runtime will create
`EgressPolicy` and use the secure TUN router. The policy continues to determine local delivery
first: the local destination does not require route allowlist, but must pass the port policy; other
destinations must pass both route and port policy. Unconfigured port rules remain at the default
value of "Only known sources can access this machine."

The message parser adds the condition "whether the port is verifiable" for TCP/UDP. IPv4 arbitrary
fragmentation, and IPv6 arbitrary fragmentation with a Fragment Header, do not produce `PacketMeta`
that can be used by the port ACL; therefore, they are rejected by `EgressPolicy::authorize()`. This
conservative rule also rejects first slices to avoid maintaining reorganization status on egress
that can be resource exhausted. ICMP/ICMPv6 fragmentation does not pass port ACLs and is therefore
also rejected at parsing boundaries, keeping implementation and security semantics consistent.

### Identity normalization

When verifying the configuration, each peer public key is first decoded into Ed25519 key and then
compared with the `encode_public()` output; non-canonical text is directly rejected. The
configuration must also deny two peers from using the same decoded public key. This way handshakes,
source name mappings, and peer identity lookups can all safely use stable one-to-one relationships.

### life cycle

`DaemonSupervisor` provides managed spawn operations that can be reused by internal runtime
components. All long-term Link control processors, physical dispatchers, capacity listeners, relay
workers, TUN receiving workers and sender workers must hold the same cancellation token and complete
the join in normal shutdown / startup rollback. Cancellation priority is collaborative: the
supervisor triggers the token first and gives the worker a short, fixed cleanup window to perform
its sub-task cleanup; if the worker does not observe the token, it discards its future and releases
the endpoint and stream it holds to avoid a single missed loop from exhausting the entire configured
shutdown deadline. A graceful shutdown will also first close the registered Link, wake up the
protocol reader, and then wait for the managed task. Even a short-lived, best-effort CLOSE with an
explicit timeout is registered with the supervisor, so shutdown can cancel or join the task without
leaving a future that breaks away from daemon ownership.

Failure to send routes will mark both the Link and the current route binding as unhealthy and
trigger a snapshot refresh. Cooling recovery must restore Link's healthy state and the original
binding at the same time: the new snapshot initializes the binding with Link state; only restoring
the old binding that has been replaced will make the new snapshot permanently unhealthy. Before
restoring, you must confirm that the Link instance has not been closed, and the reconnecting path
cannot be reactivated by the cooling timer of the old instance. Recovery edges continue to trigger
refreshes, so the same exit re-enters the candidate set.

The native management socket is part of the daemon lifecycle: the listening loop must observe the
same cancellation token; each client request sets a total processing timeout and is limited by the
bounded concurrency semaphore. The listener joins all Accepted request handlers after stopping
receiving; the handler inherits the cancellation token to ensure that half-written, unsent request
bodies or native clients that block writeback cannot remain after stopping.

The Prometheus metrics listener uses the same cancellation token and bounded concurrency model. It
joins the Accepted request task after stopping listening; the read, generate, and writeback shared
processing timeout for each request. Therefore, the network client cannot take the metrics subtask
out of the daemon life cycle, nor can it occupy workers indefinitely when reading responses slowly.

The TUN router cancels and waits for its internal task group on drop or explicit shutdown;
Link-derived work exits on Link shutdown or daemon cancellation. Network routing, firewall, and TUN
resources can only be cleaned up after these workers have exited.

### Configuration immutability

After the daemon is started, it no longer accepts reload requests, and the status socket does not
expose reload operations. All configuration modifications, including paths and migration parameters,
require a full reboot. In this way, `Runtime` no longer needs to maintain the initial configuration
and replaceable configuration snapshots at the same time. When shutting down, resource ownership
always corresponds to the same configuration that was verified at startup.

## Protocols, compatibility and security implications

The wire format, key derivation, and network handshake content are unchanged. Previous
configurations with blank public key text or duplicate peer identities will be rejected as part of a
security configuration fix at startup. TCP/UDP/ICMP fragmentation will change from "behavior is
undefined and may bypass port ACL" to definite deny; deployments that need to transport large
packets should rely on existing MSS/MTU convergence and not inner IP fragmentation. `tinect reload`
and the corresponding status socket request are removed, and automated deployment must restart the
service instead.

This design enables native service ACLs to work even without Internet egress NAT, and allows deny
paths to continue to import existing ACL telemetry. The relay still does not decrypt the end-to-end
payload.

## Migration and deployment

Before deployment, check whether peer `public_key` is standard base64-no-pad encoding without
whitespace, and each identity appears only once. Traffic that relies on inner IP fragmentation
requires MTU adjustment or application send size. Configuration updates will restart the daemon
according to the existing service management process.

## Testing and Acceptance

- Unit tests cover native allow/deny for `allowed_local_ports` only, unknown source default deny,
  and non-native no route ACL deny.
- The unit test covers the first/non-first fragment of IPv4 and IPv6 Fragment Header and is not
  allowed by the port ACL.
- Configuration tests cover non-canonical and duplicate peer public key rejections.
- Life cycle test coverage: After the supervisor is canceled, the worker can complete its sub-task
  cleanup. Workers that have not observed cancellation will also stop after the fixed cleanup
  window; the management socket and metrics listener will cancel and join the Accepted idle
  client, and the network cleanup will occur afterwards.
- CLI and management protocol testing confirmed that reload operations are no longer accepted.
- Pass `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo
  test`; perform network testing with native TUN ACLs in a privileged test environment when
  necessary.

## Open Questions

If there is indeed a need to carry inner IP fragmentation in the overlay in the future, a bounded,
circuit/source isolated reorganizer and its memory, timeout and ACL semantics should be designed
separately and cannot be implicitly relaxed in the port parser of this RFC.

## Implementation Notes

Implemented independent ACL installation, sharding fail-closed, public key normalization and
deduplication, managed worker lifecycle and removal of reload CLI/management opcodes. The native
management socket adopts cancellation token, bounded concurrency and total request timeout; the
metrics listener adopts the same managed request life cycle; the supervisor will wait for a short
cooperative cleanup window after cancellation, and then stop the non-cooperating workers to prevent
them from exhausting the global shutdown timeout. The best-effort CLOSE of hard revoke is also
supervised by supervisor. Link's QUIC capacity monitoring and bare-PMTU workers are also returned in
the form of futures that can be registered by `DaemonSupervisor` to avoid carrier internal bare
spawn bypassing shutdown join. Unit and CLI regression tests, as well as `cargo fmt --check`, `cargo
clippy --all-targets --all-features -- -D warnings `, ` cargo test` all passed.
