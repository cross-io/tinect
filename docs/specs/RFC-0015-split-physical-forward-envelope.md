# RFC-0015: split-physical-forward-envelope

- Number: RFC-0015
- Title: split-physical-forward-envelope
- Status: Implemented
- Created: 2026-07-26
- Last updated: 2026-08-15
- Change record: 2026-07-26 Review revision - Calibrate relay CPU target (cipher vs Poly1305 AAD),
  clarify empty CT and relay non-rewrite semantics, and strengthen the replacement instructions
  for RFC-0001 line format. 2026-08-15 Clarified that the Physical Forward overhead is still 25
  bytes, and the user IP capacity unit is uniformly defined by RFC-0037.

## Background and Problem

Currently Forward puts the entire end-to-end circuit frame into Physical AEAD. To select the next
hop, the relay must decrypt the inbound Physical AEAD and re-encrypt the complete frame containing
the large circuit ciphertext to the outbound Physical AEAD. Although the relay does not decrypt the
inner IP payload, each hop still performs an additional AEAD decryption and encryption of the large
chunk of end-to-end encrypted ciphertext.

It is necessary to retain the hop-by-hop confidential CircuitId, circuit sequence, end-to-end AEAD
tag and Forward metadata, while allowing the end-to-end circuit ciphertext to be transported as it
is at the relay. The ciphertext must still be bound by the integrity of the current hop Physical
AEAD and cannot be replaced by an attacker or paired with another tag.

## Goals and Non-goals

Target:

- Avoid the relay performing hop-by-hop **ChaCha20 encryption/decryption** on large chunks of
  circuit ciphertext (the old format puts the entire Forward including bulk CT into the Physical
  AEAD plaintext).
- Keep the boundaries of the relay using CircuitId table lookup and only forwarding without
  decrypting the inner IP payload.
- Leave the CircuitId, circuit sequence, circuit AEAD tag, and Forward metadata still invisible to
  current physical neighbors.
- Maintains full hop-by-hop encryption of the topology.

Non-goals:

- Reduce the main length of on the wire packets, change circuit ECDH, DATA nonce or end-to-end
  replay semantics.
- Eliminate all Physical AEAD work on the relay, or have the relay verify/modify the end-to-end
  circuit plaintext.
- Make the relay's **integrity calculation** for bulk CT O(1): the circuit ciphertext is still
  covered by Poly1305 as part of the Physical AAD, and the MAC cost is still of the same order as
  the CT length (see "MTU, Performance and Privacy").
- Prevent cross-link passive observers from correlating traffic with the same ciphertext, length,
  and timing.

## the term

- **circuit ciphertext**: The encrypted bytes of the end-to-end DATA AEAD, excluding its 16-byte
  tag.
- **circuit metadata**: `CircuitId`, circuit sequence and circuit AEAD tag; v1 has no other
  Forward metadata.
- **Physical metadata**: Encrypted circuit metadata on the current physical Link.
- **outer form**: Plain text Physical frame type, currently `Forward`, `Topology`, `PMTU Probe` or
  `PMTU ProbeAck`.

## Data format

All integers are big endian. The end-to-end nonce, AAD, key derivation and replay window of circuit
DATA still follow RFC-0007: the nonce is `0x00000000 | circuit_sequence` and the AAD is `circuit_id
| circuit_sequence`. The sender splits the AEAD output into ciphertext and a final 16-byte tag.

The complete registration form for the Physical outer form is below. The form is clear text and is
retained by the AAD authentication corresponding to the Physical AEAD; `0x04..=0x3f` and MUST be
discarded by the receiver. The form with bit 6 or bit 7 as `1` is illegal and the receiver must
discard it; this ensures that the bare UDP form of RFC-0014 can be stably recognized by bit 6 as
`0`.

| form | value | Physical plain text |
| --- | ---: | --- |
| Forward | `0x00` | Fixed 40-byte circuit metadata |
| Topology | `0x01` | topology payload |
| PMTU Probe | `0x02` | `probe_id:u64 | target_len:u16 | padding` |
| PMTU ProbeAck | `0x03` | `probe_id:u64 | target_len:u16` |

There is only one `u64 physical_sequence` in each sending direction of each authenticated Physical
Link; it increases monotonically across all forms of Forward, Topology, PMTU Probe and PMTU
ProbeAck, and independent counters are never reset or allocated due to form switching. Each
receiving direction also has only one Physical replay window shared across all forms. The sender
closes and re-authentication Link after `u64::MAX`. This rule ensures that the same Physical AEAD
key/nonce is never used for two different plaintexts.

Key derivation and encoding for Physical v2 are fixed as follows. Let `link_nonce` be the original
32-byte nonce in Hello, not its Base64 text; `sender_node_id`, `receiver_node_id` be the original
`bytes[16]` NodeId defined by RFC-0007. Arrange the Ed25519 public keys of both parties in
dictionary order as `first_public_key` and `second_public_key`; `direction` is `0x00` (first→second)
or `0x01` (second→first).

```text
physical_kdf_domain = "tinect-physical-payload-v2\\0"

HKDF-SHA256(
  salt = physical_kdf_domain,
  ikm = X25519(local_static_private, peer_static_public),
  info = first_public_key:bytes[32] | second_public_key:bytes[32] |
         link_nonce:bytes[32] | direction:u8
)
```

Physical AEAD is fixed to `ChaCha20-Poly1305`, and tag is fixed to 16 bytes. The nonce of each
Physical frame is exactly `0x00000000 | physical_sequence:u64(be)`, which is 12 bytes; it is paired
with the above directional Physical key. Except for different forms, all forms use the same
algorithm, nonce construction, and detached-tag encoding.

Forward's Physical AEAD AAD is exactly:

```text
form:u8 | physical_sequence:u64(be) | circuit_aead_ciphertext |
sender_node_id:bytes[16] | receiver_node_id:bytes[16] |
link_nonce:bytes[32] | direction:u8
```

The AAD of Topology, PMTU Probe, and PMTU ProbeAck use the same splicing, but the
`circuit_aead_ciphertext` field is omitted (that is, the field length is zero). All fields are
concatenated directly in the order of presentation, without strings, length prefixes or implicit
encoding.

Forward on the wire format is:

```text
forward_form:u8 |
physical_sequence:u64 |
physical_metadata_ciphertext:bytes[40] |
circuit_aead_ciphertext |
physical_aead_tag:bytes[16]
```

The decrypted plaintext of `physical_metadata_ciphertext` is:

```text
circuit_id:bytes[16] |
circuit_sequence:u64 |
circuit_aead_tag:bytes[16]
```

The plaintext and ciphertext of v1 metadata are both fixed at 40 bytes; `forward_metadata` must not
be appended. Therefore, the receiver reads the fixed `1 + 8 + 40` bytes from the beginning and the
16-byte Physical tag from the end. All bytes in the middle are `circuit_aead_ciphertext`, and the
format is unambiguous. The length of the middle segment can be **0** (an empty circuit ciphertext is
legal, as long as other rules of the Physical and circuit layers allow the frame); Forward that has
passed the Physical verification shall not be rejected due to "no CT". In the future, adding
hop-by-hop forward metadata must allocate a new outer form, and the fields or length of `0x00`
cannot be changed. `physical_sequence` is the Physical AEAD nonce and replay window serial number.
When it reaches `u64::MAX`, close and re-authentication Link.

Physical AEAD is encoded in detached-tag form: `physical_metadata_ciphertext` is only a 40-byte
ciphertext byte, `physical_aead_tag` is a plaintext, fixed trailing 16-byte tag, and is not
metadata. Therefore the circuit ciphertext is not encrypted by the Physical layer, but each of its
bytes is subject to current hop Physical tag authentication. The circuit AEAD tag is located within
the Physical ciphertext, and an attacker cannot forge a new Forward by replacing a set of visible
ciphertext/tags.

Topology does not use this splitting format:

```text
topology_form:u8 | physical_sequence:u64 |
topology_ciphertext | physical_aead_tag:bytes[16]
```

The complete payloads of Topology, PMTU Probe and PMTU ProbeAck are in their respective Physical
AEAD ciphertexts, and AAD is bound to outer form, physical sequence, identity of both parties, link
ID and direction. The receiver of a Probe/Ack processes its plaintext only after physical
verification and replay checks succeed; they do not enter the circuit, topology, or forwarding
queue. The clear text of outer form and physical sequence appears to select the parsing method,
construct the nonce and execute the replay window; they do not carry circuit labels.

`quicfull://` and `quicfull-faketcp://` do not use RFC-0014's bare UDP PLPMTUD. When they receive
`0x02` or `0x03`, they must first complete the Physical AEAD and shared replay window check, and
then silently discard: they must not reply to Ack, update PMTU, enter the forwarding/topology queue,
or refresh Link liveness. Its PMTU responsibilities continue to rest solely with Quinn DPLPMTUD.

The bare UDP carrier of RFC-0014 adds `destination_receive_id:u32` after `physical_form`, and then
carries `physical_sequence` of this RFC and the remaining Physical frame. The full carrier directly
uses this RFC format as the QUIC DATAGRAM payload.

## Relay and receive processing

The processing order of inbound Forward is fixed as:

1. Rebuild AAD with `forward_form`, `physical_sequence`, visible circuit ciphertext and Link
   binding fields, and verify the Physical AEAD tag.
2. Check the Physical replay window and decrypt the fixed size Physical metadata.
3. Use the resolved CircuitId to query the forwarding table of the inbound link.
4. The relay does not call circuit AEAD decryption, does not read circuit plaintext, and does not
   rewrite any byte of circuit ciphertext; the CT content may not be copied or transformed for
   Physical encryption and decryption. It is allowed on the forwarding path to hold a reference
   or equivalent copy of the same byte sequence for the I/O buffer, but the outbound CT must be
   exactly the same as the inbound CT bytes.
5. The outbound link allocates a new physical sequence, encrypts the metadata with its own
   Physical key, incorporates the unchanged circuit ciphertext into the new AAD, and generates a
   new Physical tag.

destination reorganizes `circuit_id | circuit_sequence | circuit_aead_ciphertext | circuit_aead_tag`
after steps 1--2 are successful, and then performs existing end-to-end circuit AEAD verification,
circuit replay check, and inner IP decryption. Any packet that fails physical or circuit
verification shall not refresh the link active time, install routing status, or enter the forwarding
queue.

## MTU, performance and privacy

The CPU account of this format compared to the old "full frame Physical AEAD plaintext" is as
follows (ChaCha20-Poly1305):

| working | old format (bulk in plaintext) | this RFC (bulk in AAD) |
| --- | --- | --- |
| Relay ChaCha20 | Encrypt/decrypt metadata+circuit CT | **Only about 40-byte metadata** |
| Relay Poly1305 | Cover metadata+CT (as ciphertext) | **Still cover the entire circuit CT (as AAD)** |
| relay circuit AEAD | not called | not called |

Therefore this RFC does not claim that relay has "zero cryptography" or O(1) MAC for bulk CT; the
main benefit is to remove bulk cipher encryption/decryption. If you need a MAC close to O(1) in the
future, you must open a separate RFC (for example, AAD only binds `H(circuit_ciphertext)` and
specifies anti-collision digests), and you cannot quietly change AAD in In Progress.

on the wire still retains the Physical tag and encryption metadata, and the total encapsulation
overhead is basically the same as the old format, only increasing the fixed bytes of the plaintext
outer form. The implementation must update `FORWARD_OVERHEAD`, carrier-local Physical capacity, and
LSA `inner_mtu` converted according to RFC-0037, path MTU, initial TUN MTU, and MSS clamp. It cannot
be assumed that the ciphertext will not occupy encapsulation space if it is not encrypted.

The current full Physical AEAD would make the entire Forward ciphertext different for each hop.
After this RFC, cross-link passive observers still cannot see the CircuitId, sequence or circuit
tag, but can correlate the same packet with the same circuit ciphertext, length and time. This
change therefore reduces traffic analysis resistance; this trade-off is explicitly accepted for the
purpose of reducing relay cipher** CPU. Topology continues full encryption without generating this
new visible ciphertext association.

## Security and Compatibility

Physical AEAD still provides hop-by-hop identity, direction, integrity, and replay protection; it
cannot replace the circuit's end-to-end AEAD, nor can the circuit AEAD replace the current hop's
Physical authentication. Incorporating ciphertext into Physical AAD ensures that any tampering is
rejected at the current hop. Hiding circuit tags in Physical metadata prevents attackers from making
offline construction attempts by combining visible tags with replacement ciphertext.

This wire format is incompatible with the RFC-0001/RFC-0007 Implemented format, and all connected
nodes must be upgraded as a whole. Does not log circuit metadata, ciphertext, probe content, keys,
or real traffic to RFCs, logs, state interfaces, or PCAP.

## Testing and Acceptance

1. Crypto/physical unit tests cover form registry and reserved/illegal form rejection,
   ciphertext/tag separation and reassembly, encryption of physical metadata,
   identity/direction/AAD binding, fixed nonce/AAD test vectors, Physical and circuit replay,
   sequence number exhaustion and truncation rejection.
2. The tamper test covers the replacement or cross combination of any byte, metadata, physical
   tag, circuit tag of ciphertext and must be rejected at the correct layer.
3. The relay test verifies that the circuit ciphertext bytes are identical for each hop, while
   the Physical metadata, physical sequence, and Physical tag change; the relay must not call
   end-to-end decrypt.
4. The Topology test verifies that the payload is still intact, physically encrypted, and the LSA
   signature, timeliness, and propagation semantics remain unchanged; continuous sending across
   Forward, Topology, Probe, and ProbeAck must use the same incremental sequence. When
   `quicfull*` receives an authenticated Probe/Ack, it must consume the shared replay sequence
   and then discard it silently, without refreshing liveness, sending Ack, or updating PMTU.
5. The real three-node test verifies A→B→C forwarding, inactive switching and recovery, MTU/MSS
   capacity, and resource cleanup; at the same time, it is checked that the ciphertext before and
   after the relay remains unchanged and the destination still refuses to be tampered
   with/replayed.
6. Optional but recommended: Relay CPU/Profiling to compare the old bulk Physical AEAD with this
   format, confirm that bulk ChaCha20 disappears and Poly1305 still grows with the CT length, to
   avoid mistakenly accepting "saving cipher" as "saving all AEAD".

## Open Questions

- None yet. Implementations should be published with RFC-0014 because the public headers of bare
  UDP refer to the outer form and physical sequence of this RFC.

## Implementation Notes

`src/physical.rs` has adopted Physical v2: Forward's 40-byte metadata to be individually encrypted,
and the circuit ciphertext enters the Physical AAD as it is; Topology, Probe, and ProbeAck still
pass through the Physical AEAD as a whole, and share a monotonic sequence/replay window. Relay
continues to only read the reassembled CircuitId and does not invoke end-to-end decryption.
