# Tinect Communication Protocol

This document describes the current implementation; design rationale, complete acceptance conditions
are provided in [RFC-0007](specs/RFC-0007-open-ecdh-binary-wire-protocol.md),
[RFC-0014](specs/RFC-0014-mixed-carrier-bare-udp-transport.md),
[RFC-0015](specs/RFC-0015-split-physical-forward-envelope.md),
[RFC-0046](specs/RFC-0046-circuit-control-simplification.md) and
[RFC-0039](specs/RFC-0039-adaptive-datagram-fec.md). The protocol does not provide a compatibility
layer for older versions.

## General rules

Integers are all big-endian; `String` and variable-length bytes are both `u16 length | bytes`;
vectors are `u16 count | elements`. NodeId is the first 16 bytes of the SHA-256 hash of the Ed25519
public key, is encoded on the wire as `bytes[16]`, and the text appears as 32-bit lowercase
hexadecimal. CircuitId is still encoded on the wire as `bytes[16]`, consisting of a random 64-bit
prefix and a monotonic 64-bit counter generated when the source process starts. There is no magic
value, version field, or reserved field.

Reliable unidirectional QUIC control streams use `type:u8 | body_length:u16 | body`. Each stream
carries one message with a maximum body size of 65,535 bytes. Truncated messages, incorrect lengths,
unknown types, invalid boolean values, and trailing bytes are rejected.

## Link establishment and control messages

During the authenticated QUIC application handshake, the carrier exchanges Hello/HelloAck messages
containing NodeId, public key, nonce, receive ID, capabilities, and an optional FEC repair rate. The
signature covers every non-signature field, and the Ack is also bound to the Hello nonce. A peer not
present in the configuration cannot establish a Link.

The control-stream message types are as follows. Except for Topology synchronization, Ping/Pong and
FecReport, Circuit lifecycle messages all carry the signature public key and signature; the
signature input is the fixed binary field of the corresponding message, excluding the outer
`type/body_length`.

| type | message | body field |
| ---: | --- | --- |
| 1 | Hello | `node_id[16] | public_key[32] | link_nonce[32] | receive_id:u32 | capabilities:u32 | [repair_rate_milli:u16] | signature[64]` |
| 2 | HelloAck | `node_id[16] | public_key[32] | receive_id:u32 | capabilities:u32 | [repair_rate_milli:u16] | signature[64]` |
| 16 | Open | `open_domain:u8(16) | circuit_id[16] | ephemeral_x25519[32] | source_public_key[32] | path_count:u16 | path:NodeId[] | signature[64]` |
| 17 | OpenAck | `circuit_id[16] | responder_public_key[32] | signature[64]` |
| 18 | OpenReject | `circuit_id[16] | retryable:u8 | reason_code:u16 | responder_public_key[32] | signature[64]` |
| 19/20 | Ping/Pong | Empty |
| 21 | CircuitClose | `circuit_id[16] | counter:u64 | reason_code:u16 | source_public_key[32] | signature[64]` |
| 22/23 | CircuitRenew/RenewAck | `circuit_id[16] | counter:u64 | public_key[32] | signature[64]` |
| 24 | CircuitBroken | `circuit_id[16] | reason_code:u16 | reporting_public_key[32] | signature[64]` |
| 25 | TopologySync | `mode:u8 | sync_id:u64 | chunk_index:u16 | chunk_count:u16 | lsa_count:u16 | LSA[]` |
| 26 | TopologySyncAck | `sync_id:u64` |
| 27 | TopologySyncRequest | `reason:u16` |
| 28 | Reserved/Unknown | Reject while decoding |
| 29 | FecReport | `report_id:u64 | samples:u32 | loss_ppm:u32 | burst_milli:u16` |

Hello and HelloAck signatures cover all of its non-signature fields (Ack also binds the connection's
Hello nonce). Open's signature covers `open_domain`, CircuitId, temporary public key, public key and
path; all signature control messages use their own wire kind as transcript domain. Open no longer
carries source, destination, TTL, path MTU or nonce: source is derived from the public key,
destination is derived from the end of the path, and control messages are only associated with
`(Link instance, CircuitId)`. The destination verifies the path, transit/relay admission and OPEN
signature, and sends the signature OpenAck only after installing the ECDH DATA session; the
decrypted user IP packet must still pass through `EgressPolicy::authorize()` separately. An
OpenReject can be signed by a destination or path node that actually rejects the OPEN, and the
source matches the waiter by CircuitId, Link instance, and allowed response identity.

`CircuitClose`, `CircuitRenew`, `CircuitRenewAck`, and `CircuitBroken` use CircuitId, a counter or
reason, and a signature to prevent stale state from being restored. `CircuitBroken` also reports
unknown sessions, missing relay labels, and downstream failures. A receiver must sign the report
even if it has already removed the binding. Each relay verifies the downstream identity, re-signs
the feedback, and forwards it. The source revokes the old lease using the first-hop Link instance
and CircuitId. If feedback is lost, the long lease, authenticated DATA refresh, and periodic Renew
provide independent recovery. A transient Renew failure does not revoke an active Circuit. Repeated
failures start a local grace period bound to `CircuitId + lease_epoch`, with a duration equal to the
long lease. Only a RenewAck with the current waiter's counter clears the grace period. On expiry,
Tinect performs a full hard revoke, removes the session, return-flow, Circuit DNS, and authorization
State, then rebuilds the Circuit.

There are no INIT, SessionInit, SessionAck, or lease_epoch fields on the wire, and active Circuits
do not rotate keys. Repeating an identical Open is idempotent. Reusing a CircuitId with a different
source or key is rejected as a rebind. Unknown receiver sessions and missing relay labels are
reported through kind 24, CircuitBroken. Its reason codes distinguish: `1`, binding removed after
the outbound Link closed; `2`, unknown receiver session; `3`, Renew rejected because the binding was
removed or did not match; and `7`, the relay aborted the binding after Renew/RenewAck forwarding
failed.

TopologySync's `mode` is Snapshot or Delta; a Delta must fit in a single chunk. A Snapshot may be
fragmented. The receiver applies it atomically only after it has been fully reassembled, validated,
and checked against size limits, then returns SnapshotAck. The LSA format is:

```text
origin[16] | sequence:u64 | expires_at:u64 | neighbor_count:u16
| (neighbor[16] | cost:u32 | inner_mtu:u16)*
| public_key[32] | signature[64]
```

The LSA signature covers all fields before signature; `inner_mtu` is the complete user IP packet
capacity, excluding Tinect DATA/Physical and carrier outer overhead. LSA only propagates graph and
directional capacity, not `peers.*.routes`, `direct.routes` or path override.

## E2E DATA and Physical datagram

The logical format of E2E DATA is:

```text
circuit_id[16] | sequence:u64 | direction:u8 | ciphertext | tag[16]
```

`direction`: `0=Forward`, `1=Return`, `2=DnsForward`, `3=DnsReturn`. The nonce is `0x00000000 |
sequence`, AAD is the first 25 bytes; the fixed overhead is 41 bytes. The source carries the
temporary X25519 public key in the signature OPEN, and the destination uses the static X25519
private key corresponding to the Ed25519 identity to derive the DATA key. CircuitId, public keys of
both parties and temporary public keys participate in HKDF. The serial number can be used up to
`u64::MAX`; after reaching the upper limit, close the Circuit and reopen it, and never wrap around
or reuse the nonce. The receiver maintains a 65,536-bit authentication replay window as `(CircuitId,
direction)`.

The first byte of each hop's Physical datagram identifies its form:

```text
form:u8 | physical_sequence:u64 | authenticated_payload
```

PhysicalSession derives hop-by-hop AEAD keys based on Link nonce, NodeId of both parties, and
direction, and performs replay checks on the sequence. Forward will encrypt the Circuit metadata
(CircuitId, sequence, direction and E2E tag) of the E2E frame hop by hop, and put the E2E ciphertext
into the Physical AAD as it is; therefore, the relay can select the next hop according to the
CircuitId, but it cannot replace or read the inner IP payload. The Tinect fixed overhead of ordinary
Forward is E2E 41 bytes plus Physical 25 bytes, a total of 66 bytes; the current actual wire limit
of the outgoing carrier is still used for final check before relay is sent.

| form | PhysicalPayload | description |
| ---: | --- | --- |
| `0x00` | Forward | Opaque E2E frame; relay only reads CircuitId |
| `0x01` | Reserved Topology | Topology only allows reliable control streams, and will be rejected upon receipt |
| `0x02` | Probe | `probe_id:u64 | target_len:u16 | padding:bytes`, used for bare Physical capacity detection |
| `0x03` | ProbeAck | `probe_id:u64 | target_len:u16` |
| `0x04` | Keepalive | Empty; authenticated keepalive for D1 adjacencies |
| `0x05` | FecSource | Add `transmission_sequence:u32 | esi:u32` before Forward framing, and the prefix enters AAD |
| `0x06` | FecRepair | `transmission_sequence:u32 | rid:u32 | first_esi:u32 | symbol_count:u16 | repair_vector`, fully protected by Physical AEAD |

`Probe`/`ProbeAck` is only used in bare Physical capacity detection; full QUIC is responsible for
the conversion of Quinn DATAGRAM capacity and user capacity of the same Link. When the physical
sequence is exhausted, the link must be closed and re-authenticated.

### Datagram FEC

FEC is an independent datagram recovery for each link, not an end-to-end protocol. The optional
`repair_rate_milli` in Hello/Ack is the repair upper limit of each source datagram; if either side
is missing or zero, the FEC of the Link is closed. The source symbol logical content is
`frame_len:u16 | complete E2E frame`, using bounded GF(256) sliding window. The receiver only
publishes the complete source/recovered frame to the dataplane; the relay re-encodes independently
on the next Link.

The receiver first performs repair window and credit admission, and then enters the decoder;
expired, illegal or excessive repair will not be disguised as path packet loss. Link-local FEC
feedback uses a reliable control stream of type 29, and is retried by an independent worker bounded
until the Link is closed, without being forwarded through the Circuit relay. When FEC is enabled,
the capacity budget is calculated based on the worst repair packet: the physical capacity is reduced
by 66 bytes for a normal link, and 82 bytes for the FEC link.

## Local management socket

Unix socket requests use `opcode:u8 | body_length:u16 | body`; responses use
`opcode:u8 | status:u8 | body_length:u16 | body`. EOF marks the end of the exchange. Opcodes are:
1 Status, 2 Routes, 3 Topology, and 4 PCAP; status 0 indicates success. The socket is owned by the
daemon and has mode `0600`. Configuration does not support hot reload, so the management interface
has no Reload opcode. Circuit status records include local preferred-path migration state. These
fields belong to the local management interface and are not part of the network Circuit wire
format. The CLI renders responses as JSON, DOT, or PCAP files; those display formats are not part of
the wire protocol.

## Known limitations

The E2E replay window is fixed at 65,536 bits, and each physical Link also uses a bounded replay
window. The protocol does not provide backward compatibility or key rotation. A node restart is a
stateless boundary for Circuit state; existing Circuits are not restored.
