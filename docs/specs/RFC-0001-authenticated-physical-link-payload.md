# RFC-0001: authenticated physical link payload and topology notification

- Status: Implemented (**Forward Wire Format and Relay Repackaging Rules** Superseded by RFC-0015,
  see below)
- Created: 2026-07-20
- Last updated: 2026-07-26

## background

> Follow-up note (2026-07-26): RFC-0015 clarifies **Supersedes** The following in this RFC:
  Forward puts the entire circuit frame into the wire format of Physical AEAD plaintext, the rules
  for relay hop-by-hop re-encryption of the entire frame, and the bulk encapsulation assumptions
  bound to it. Topology's complete encryption, Physical identity/direction binding and replay
  **target** are still based on this RFC; when implementing Forward, it must be based on RFC-0015
  and must not be encoded according to the old Forward frame layout of this RFC.

Existing link keepalives rely on QUIC empty DATAGRAM, independent control flow, and topology
broadcasts. Empty DATAGRAM neither overlay network identity binding nor proof that the peer handles
the overlay network protocol; the keepalive for each circuit will also grow linearly with the number
of circuits. The three-node scenario requires that the A→B→C main path and A→C backup physical link
be retained at the same time: when B is available, B will be relayed first. After B fails, A must
switch to C within the inactivation window, and then switch back to the priority path after B
recovers.

## Target

- Only actual QUIC adjacency Link keepalives, no circuit-level heartbeats are added.
- Each physical payload has confidentiality, integrity, peer identity and direction binding, and
  replay protection.
- Ordinary data, relay forwarding, and topology payload all refresh the physical link active time.
- Idle keepalives and topology declarations use the same authentication payload; LSA still uses
  the origin signature as authoritative.
- Keep the default 10 second keepalive interval and 35 second active receive inactive threshold.

## Non-goals

- Does not change the trust model of end-to-end circuit encryption.
- Does not allow the relay to decrypt, inspect, or modify the end-to-end inner IP payload.
- QUIC transport keepalives are not considered the only evidence of overlay network survival.

## the term

- **Physical Link**: Two QUIC adjacency connections that have completed Tinect authentication.
- **Physical payload**: Encrypted, authenticated DATAGRAM content on a physical Link.
- **Forward**: carries the physical payload of the original end-to-end encrypted circuit frame.
- **Topology**: The physical payload carrying one or more signed LSAs.
- **LSA**: Link-State Advertisement with sequence and expiry signed by the origin identity.

## design

### Payload and key

Define versioning `PhysicalPayload`:

```text
Forward { encrypted_circuit_frame }
Topology { advertisements }
```

Each authenticated QUIC Link uses the X25519 shared secret obtained from the Ed25519 identity
conversion of both parties, and combines the handshake nonce/link id with HKDF to derive a
bidirectional independent AEAD key. The packet contains the protocol version and monotonic sending
sequence number; AEAD AAD binding version, link id, sender identity, receiver identity and
direction. Each receive direction maintains a limited replay window.

Payloads that are not authenticated, tampered with, replayed, do not match versions, or have
inconsistent directions must be discarded, special observable events logged, and `last_rx` must not
be refreshed. The receiver cannot terminate the Link's receive cycle due to a bad payload.

### Data and relay

When sending circuit data, encapsulate the original end-to-end encrypted frame into `Forward` and
send it. The relay only opens the current physical layer, reads the local label of the opaque
circuit frame to select the next hop, and then re-encapsulates `Forward` with the physical key of
the next hop Link. The relay must not call end-to-end decryption, nor must it modify the inner
frame.

Successful delivery of `Forward` and `Topology` updates `last_tx`; any payload that passes physical
AEAD verification updates `last_rx`.

### topology and keepalive

The timer only scans actual physical Links:

1. If `now - last_tx >= keepalive_secs`, send `Topology` payload.
2. The payload carries at least the latest LSA of this node, and carries as many verified LSAs as
   possible to be forwarded in batches within the current DATAGRAM size limit.
3. Any real data, relay forwarding or topology payload suppresses extra heartbeats.
4. If `now - last_rx >= 35s`, close the Link, delete the direct adjacency relationship and
   trigger circuit recalculation.

After receiving `Topology`, the origin signature, sequence, expiry and self-loop verification of the
original LSA must be performed first; only the newly accepted LSA can be forwarded to the actual
adjacent link except the inbound link. Control flow is still available for `Open`, reliable session
establishment, and ACKs, but LSAs are no longer carried.

## Security and Compatibility

- Link AEAD is a hop-by-hop protection and cannot replace the origin signature of LSA, nor the
  end-to-end encryption of circuit.
- Physical encapsulation overhead must participate in the effective MTU calculation.
- Older nodes do not understand the physical payload; this protocol change requires an overall
  upgrade of connected nodes, or the introduction of an explicit negotiation/version migration
  scheme in the future.
- Do not log payload plaintext, private keys, or handshake secrets to the state interface, logs,
  or PCAP.

## Testing and Acceptance

Unit tests must cover:

- `PhysicalPayload` Encryption/decryption, identity and direction binding, tampering and replay
  rejection.
- Data sending suppresses idle keepalives and updates activity time; idle Link sends
  authentication topology payload.
- Link deactivates after 35 seconds of not receiving a valid physical payload.
- The relay only re-encapsulates `Forward`, leaving the end-to-end inner payload unreadable and
  unmodified.
- Topology batches retain LSA signatures and reject expired and replay LSAs.

Three node acceptance sequence:

1. Start A/B/C and confirm that A→B→C is the active path; first ping the C overlay IP, then send
   the target traffic into the TUN through policy routing, and finally ping the egress.
2. B runs normally for more than 35 seconds, confirming that the A→C backup physical link is
   healthy.
3. Stop B, confirm that A switches to A→C after the deactivation window, and successfully
   outbound in the same ping sequence.
4. Restore B, confirm that A again gives priority to A→B→C, and A→C remains healthy and available
   for backup.
5. Stop all daemons and confirm that TUN, temporary routes, nft rules, and status sockets have
   been cleared.

## Implementation Notes

The implementation is complete and passes native Rust checks (`cargo fmt --check`, `cargo clippy
--all-targets --all-features -- -D warnings `, ` cargo test`).

Three-node acceptance covers the A→B→C main path, A→C backup physical link, path switching and
recovery after B stops, as well as TUN, routing and status socket cleaning.
