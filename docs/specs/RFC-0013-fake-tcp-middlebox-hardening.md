# RFC-0013: fake-TCP middlebox hardening

- Number: RFC-0013
- Title: fake-TCP middlebox hardening
- Status: Implemented
- Created: 2026-07-26
- Last updated: 2026-08-15

## Background and Problem

QUICP hosts QUIC DATAGRAM in a minimal fake-TCP form factor. On some cross-border ISP paths, the
actual measurement is the same as on the underlay:

- `quic://` (true UDP) up to ~17 MB/s, `loss_ppm ≈ 0`
- Old `quicp://` (Window Scale only SYN, data segment only ACK, no PSH) ~0.7–0.9 MB/s under load
  `loss_ppm ≈ 2500–3000`

It shows that the bottleneck is not the underlay bandwidth or tinect encryption itself, but the
**fake-TCP shape triggering middlebox soft packet loss**, which is then amplified by "real TCP over
unreliable DATAGRAM".

The old form factor is too different from common host stacks:

1. SYN only has Window Scale, no MSS
2. The application data segment only has ACK and no PSH
3. When arriving out of order, the latest serial number will be used unconditionally to advance
   `receive_next`. The ACK number will be rolled back, making it easier for the state firewall
   to detect abnormalities.

## Goals and Non-goals

Goal: Without introducing TCP retransmission/congestion control, make on the wire packets closer to
the common TCP host stack, reduce the probability of soft packet loss in the middle box; and ensure
that the ACK sequence number is monotonous and does not fall back.

Non-goals:

- Implementing true TCP reliable transmission or congestion control (still the responsibility of
  QUIC)
- Ensure quicp reaches quic throughput on any ISP
- Change QUIC / physical / Session frame format

## design

1. **SYN option (20 bytes)**: `MSS` + `SACK-permitted` + `Timestamp` + `NOP` + `Window
   Scale(shift=7)`. IPv4 MSS=1460, IPv6 MSS=1440. Data offset 10 (40-byte TCP header).
2. **Created segment option (12 bytes)**: `NOP NOP Timestamp`, including `TSval`/`TSecr` echo;
   data segment flags are `PSH|ACK`, pure ACK is still `ACK`.
3. **Ordered ACK**: Advance `receive_next` only when `sequence == receive_next`;
   out-of-order/duplicate payloads are still handed to QUIC, but the ACK field is not rolled
   back.
4. **PMTU upper limit**: Data TCP header 32 bytes → IPv4/IPv6 QUICP path-payload upper limit is
   1448/1428; full QUIC application DATAGRAM upper limit is 1410/1390 (relative to the old
   1460/1440 path-payload configuration).
5. **Handshake compatible**: `SynReceived` accepts `ACK` or `PSH|ACK`; `decode` ignores unknown
   options and old nodes can still communicate (may not echo Timestamp).

## Security and Compatibility

- Still not doing TCP reliability; packet loss semantics are consistent with RFC-0010.
- Old and new QUICP nodes: new nodes can parse old packets; old nodes can parse new packets
  (unknown option lengths are ignored, as long as the header length is legal). The old node does
  not recognize PSH but will treat PSH|ACK as a data segment (`flags & SYN == 0` path).
- No new authorization boundaries are introduced; RST guard blocks kernel RST by port by default.
  After configuring Linux `fwmark`, use packet mark to distinguish kernel RST and raw socket
  packets.

## Session resource life cycle (2026-07-31)

The TCP profile of fake-TCP can be triggered by any network packet before QUIC authentication, so
the session table cannot treat semi-connections as trusted or permanent resources.

1. Each session records the last valid peer progress; successful local writes to an established
   session can also refresh the activity time. SYN/SYN-ACK retransmissions initiated only by the
   local machine must not refresh it to avoid forged SYNs being retransmitted by the local
   machine and kept permanently.
2. `SynSent`, `SynReceived` and other unestablished states are recycled after 10 seconds of
   inactivity; `Established` state is recycled after 5 minutes of idleness. Recycling and
   retransmission share a 250ms maintenance tick. Recycle first and then decide to retransmit.
3. When the expression reaches 4096 items, the new tuple can only eliminate the unestablished
   session that has been inactive for the longest time; the `Established` session cannot be
   eliminated. If all entries have been established, new tuples are rejected, keeping existing
   streams from being squeezed out by unauthenticated SYNs.
4. This resource policy does not change the wire format of QUIC, Physical, or fake-TCP; after
   timeout, the peer is handled by QUIC's own connection/handshake recovery.

## Testing and Acceptance

1. `tinect-fake-tcp` unit tests: SYN option layout, PSH data, out-of-order ACK no fallback,
   IPv4/IPv6 round trip.
2. `cargo test` / `clippy -D warnings` / `fmt`.
3. Optional live: Execute `quicp` HTTP download of the same path on the actual deployment link,
   and compare `loss_ppm` and throughput before and after the change (not used as a CI
   threshold).
4. session-table unit test coverage: half-connection timeout, Established idle timeout, full
   table elimination of the oldest half-connection, Established session not eliminated, and full
   Established table rejection of new sessions.

## Hot path optimization (continued from RFC)

When quicp is still about half of underlay after 0 packet loss, append:

1. **pure ACK does not merge**: Each established segment with payload will immediately send pure
   ACK (including out-of-order); delayed-ACK merging will not be performed to ensure that there
   is still a stable ACK rhythm in the reverse direction during one-way bulk. The PSH|ACK of
   `encapsulate` itself has piggybacked the confirmation number.
2. **Single decode**: `handle_packet` / `accept_packet` for quicp to reuse the decoded `Packet`
   to avoid `receive_one` double `decode`.
3. **Clock**: Timestamp uses `Instant` (vdso), avoiding hot path `SystemTime`.
4. When quicp sends reply, it uses **move instead of clone**.
5. **Single payload encoding**: `encode_with_payload` directly configures wire from `&[u8]`;
   `emit` is no longer secondary allocated to `Packet.payload` (wire is authoritative; the
   on-wire appearance is not changed).
6. **Batch recv**: `RawTcpSocket::try_recv` (`MSG_DONTWAIT`) + `poll_recv` `poll` first and then
   non-blocking drain, filling multiple Quinn `RecvMeta` at one time (without changing the
   on-wire appearance).

## Implementation Notes

- `crates/tinect-fake-tcp/src/lib.rs`: MSS/SACK/TS SYN, data segment TS+PSH, ordered ACK, pure ACK
  per data segment (no merging), `handle_packet`, `encode_with_payload`.
- `src/carrier/quicp.rs`: single decode, reply move, batch `poll_recv`.
- `src/platform.rs`: `try_recv` / Share `recv_into`.
- `src/mtu.rs`: The upper limit of the datagram corresponding to the 32-byte TCP header of the
  data segment.
- Document: `crates/tinect-fake-tcp/README.md`; RFC-0010 SYN/data header length description.
