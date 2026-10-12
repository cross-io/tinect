# RFC-0048: Review hardened boundedness and verification

- Number: RFC-0048
- Title: Review Reinforced boundedness and verification
- Status: Implemented
- Created: 2026-09-03
- Last updated: 2026-09-03

## Background and Problem

2026-09 Overall review found a batch of feedback paths and configuration verification gaps that grew
unbounded and blocked the data plane:

1. `UnknownSession` feedback is inline `await` in the data plane receiving loop. Each miss costs
   up to `3×500ms` to control admission waiting; an attacker can stall legitimate traffic by
   spraying different `CircuitId`.
2. `Router.closed` tombstone is only cleared when `remove_bindings`, there is no upper limit;
   sequential open/close on the same Link can increase the memory without bounds.
3. `abort_relay_binding` does not write tombstone. `CircuitId` that has just been cleared after
   failure can be immediately resurrected by a new OPEN with different path/key.
4. The top-level `fwmark: 0` is silent no-op (`SO_MARK 0`), and does not verify equality with
   `direct.fwmark`; the two have different mark semantics, and equality will confuse `ip rule` /
   nft / RST-guard.
5. Derived from `Config`, `Debug` directly prints `identity_key` and `fake_tcp_reset_key`.
6. `OPEN.path` Only `u16 count` has the upper limit (~4k hops), and hop-by-hop clone/forwarding
   can be amplified.
7. Circuit DNS `pending` is unbounded, `total: u16` is not authenticated, which is `resize`.
8. direct fallback: When the flow table is full, it is randomly evicted according to hash, and
   can be churned by the attacker into legitimate flows.
9. `should_report_circuit_broken_feedback` `retain()` full table scan each time (O(N)/packet).
10. `RouteSourceSelector::Nodes([])` is fully allowed via `all()` fail-open.
11. `physical` probe padding has no upper limit, repair vector decoding boundary and encoding
    boundary are inconsistent.
12. `ReceiverSessions::install_*` Use `or_insert` to silently retain the old key.
13. `RenewAck` relays first and then verifies the signature; `CircuitBroken` accepts the unknown
    reason code and revokes it.
14. `pcap_buffer_packets` has no upper limit; `--node` accepts `.`/`..`; `carrier_interface` is
    only verified at the carrier layer (`tinect check` passes by mistake on Linux).

## Goals and Non-goals

Goal: All the above bounded/verified, no behavioral regression; return path semantics remain
unchanged.

Non-goals: split the 5.5k-line daemon file, change `SecureRoute` to `LinkRef`, make the TUN handle
opaque, and return `Runtime::new` to `Result`. These structures are highly risky to refactor and are
left to follow-up RFCs.

## design

- Feedback asynchronousization: `receive_secure_link` and relay worker only make `should_report_*`
  current limit judgment, and `send_circuit_broken_feedback` is actually sent through
  `DaemonSupervisor::spawn_background` background; the receiving loop will never block.
- The upper limit of `closed` is `MAX_CLOSED_BINDINGS = 4096`. When full, tombstones of the same
  incoming Link will be evicted first (limit the churn radius to this link); `abort_relay_binding`
  and lease expiration (`expire_due_bindings`) are also written as tombstones. `handle_open` has
  returned `Rebinding` for tombstone, and the immediate re-OPEN after abort/expiration will be
  rejected.
- `fwmark`: The top-level `Some(0)` is rejected; the top-level and `direct.fwmark` are configured
  at the same time and are rejected when they are equal.
- `Config` handwriting `Debug` (`identity_key` desensitization), `FakeTcpResetKey::Key` printing
  `[redacted]`.
- The upper limit of the OPEN path is `MAX_OPEN_PATH_HOPS = 16`, which is executed consistently at
  `decode_body`, `verify`, and `validate_open`. If the limit is exceeded, it is rejected by
  `InvalidPath`.
- Circuit DNS: `MAX_PENDING_DNS_QUERIES = 256` (when full, evict the oldest in insertion order and
  send `Err` to the evicted, no longer silent hang), `total <= MAX_DNS_RESPONSE_CHUNKS = 64`, `<=
  900B` per chunk. Illegal range chunks still retain query state for recovery (DATAGRAM is
  unreliable, valid chunks may still be reached after bad chunks; 5s timeout guarantees), only
  `status != 0`, assembly completed, link/circuit cleanup and timeout/cancel removal query. The
  64×900B upper limit keeps the assembly bytes below `MAX_DNS_RESPONSE_BYTES = 65535`
  (`debug_assert` guard, no hot path accounting required).
- The direct flow table is changed to `HashMap<flow, seq> + BTreeMap<seq, flow>`, and the oldest
  is evicted when full. Insertion/deletion/eviction are all `O(log N)`.
- `should_report_*` looks up the key and checks its TTL first (re-report when expired). When the
  table `>= 1024` is used, the inert full table sweep is performed. Under full table pressure,
  expired entries are first recovered and then rejected.
- `Nodes([])` matches empty; `MAX_PROBE_PADDING_BYTES = 65535`; the repair vector decoding world
  is unified to `MAX_SYMBOL_BYTES`.
- `install_direction` When the installation is repeated and the source is inconsistent, the
  original session is retained and `warn` (the crypto layer has no observability handle, and warn
  is enough to discover the stuck pre-rotation key).
- `RenewAck` is preceded by `verify_renew`, and the arrival link constraint of `reverse_relay` is
  reused (ack must reach the actual downstream link of the circuit). Residual: The relay cannot
  verify that the ack signer is exit (the binding stores the source key). The forger wastes at
  most one admission forwarding per hop, which is the same as the RENEW/CLOSE relay; the source
  side `resolve` rejects the wrong key/counter as usual. Exit identity verification requires
  path-to-key search, which is left for later.
- `CircuitBroken` ignores reason code `warn` other than `1/2/3/7` (renewal/lease grace still
  retains convergence).
- `pcap_buffer_packets <= 65536`; `--node` rejects `.`/`..`/control characters;
  `carrier_interface` checks for NUL, macOS-only, fake-TCP mutual exclusion in `Config::validate`.

## Return path description (High-4 conclusion)

The return path skipping `EgressPolicy` is a design rather than a defect: `EgressPolicy`
authorization is the forwarding of the egress to the Internet/local port, while the return packet is
returned to the source TUN along the established, E2E authenticated circuit. Return is triple
protected: `is_authorized` (circuit binding), directional DATA key decryption, `SourceAddressPolicy`
(`bind_addresses` / `routes[].bind`, `dataplane.rs` return branch has been called). Adding
`EgressPolicy` to return will accidentally kill the legitimate return packet (the destination
address is a TUN address and cannot pass the export check). This time only comments and regression
tests are added, and the semantics are not changed.

## Security and Compatibility impact

- Old configurations for `fwmark: 0`, equal marks, and out-of-limit pcap/path/DNS chunks now fail
  to start; these configurations were previously either meaningless (`SO_MARK 0`) or unsafe and
  required explicit correction.
- The rest are pure reinforcement: normal traffic is insensitive, and the attack surface
  (CPU/memory stall, fake relay, random eviction) converges to bounded.
- Keys no longer enter log/panic via `Debug`.

## Testing and Acceptance

- New single test: `debug_redacts_identity_and_reset_keys`,
  `top_level_fwmark_must_be_nonzero_and_differ_from_direct`, `pcap_buffer_is_bounded`,
  `empty_node_selector_matches_nothing`, `closed_tombstones_are_bounded`,
  `closed_tombstone_eviction_prefers_the_churning_link`,
  `aborted_relay_binding_rejects_immediate_reopen`, `open_paths_are_bounded_everywhere`,
  `overlong_open_paths_are_rejected_at_decode_and_verify`,
  `path_length_is_bounded_by_max_open_path_hops`,
  `dns_response_chunks_are_bounded_but_keep_state_for_recovery`, `replay_window contains`,
  `duplicate_install_with_mismatched_source_keeps_original_session`,
  `control_decode_rejects_oversized_probe_and_repair_vectors`.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`
  passed.

## Open Questions (Updated on 2026-09-04: Four of the structural reconstructions have been completed)

- ~~Split `control_handler.rs` / `circuit_reconciler.rs` (~5.5k lines each)~~ — Completed:
  `control_handler/{helpers,tests}` and
  `circuit_reconciler/{context,revoke,migration,candidate,renewal,open_worker,retry,tests}`.
- ~~`SecureRoute.link: Arc<Link>` changed to `LinkRef`~~ — completed, covering
  `QueuedSecurePacket`/`ReturnTarget` at the same time; `attach_link` and the receiving path
  maintain the specific type.
- ~~`platform::TunDevice` Opaque handle~~ — Completed, `tun_name` has been changed to private.
- ~~`Runtime::new` Return `Result`~~ — Completed.
- Remaining: `anyhow!(e.to_string())` changed to typed errors + `.context()` (only the network
  assembly part has been prefixed with context, and Display still retains the inner original text
  to be compatible with existing assertions).
