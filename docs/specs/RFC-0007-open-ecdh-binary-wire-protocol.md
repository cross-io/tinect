# RFC-0007: OPEN ECDH and binary wire protocol

- Status: Implemented (**Hello Receive ID and Physical DATAGRAM line format** See RFC-0014/0015)
- Created: 2026-07-24
- Last updated: 2026-08-28

> RFC-0046 updates and replaces the OPEN and Circuit control message wire definition of this
  article: CircuitId is the only Circuit token, OPEN no longer carries open nonce, TTL or path
  MTU, and the signature transcript adds wire kind. The old field table in this article is
  retained for historical context only; the current format is based on `docs/protocol.md` and
  RFC-0046.

## background

> Follow-up Notes (2026-07-26): RFC-0014 **Supersedes** Correlation line format and semantics of
  Hello/HelloAck receive ID on carrier side in this RFC (global non-zero `sender_receive_id`
  exchange; bare UDP re-lead). RFC-0015 **Supersedes** The frame layout and Physical packaging
  description of Forward/Physical DATAGRAM in this RFC. EC-DH DATA key derivation, circuit DATA
  nonce, AAD, and end-to-end replay rules still apply unless explicitly modified by RFC-0015 or
  RFC-0046. RFC-0037 further clarifies that the actual fixed overhead of DATA is 41 bytes, and
  unifies the LSA/OPEN capacity field to the full user IP packet capacity; the field position and
  width remain unchanged.

v2 uses a 32-bit deterministic label as a common index for forwarding tables, sessions, and ACKs,
and there is a risk of collision coverage. It also places the INIT that establishes the end-to-end
session in a separate control message and uses JSON for the inter-node control flow, topology
payload, and local management interface. JSON signature bytes are implementation-dependent
serialization details, and control flow has a fixed 4096-byte limit that is inconsistent with actual
field boundaries.

## Goals and Non-goals

Goals: Compose a 128-bit CircuitId with a random 64-bit prefix and a monotonic 64-bit counter to
avoid reuse during the process life cycle and isolate node restarts with a random prefix; complete
ECDH by reliable OPEN and mount DATA sessions directly; use deterministic binary encoding for all
inter-node and local Unix management interfaces; make all fields, lengths and signature inputs
clear.

Non-goals: retain v2 interoperability, modify the best-effort semantics of QUIC DATAGRAM, modify
ACL/NAT, let the relay decrypt the inner IP packet, or implement cross-process/cross-link key
persistence.

## universal encoding

All integers are big endian. Boolean is a byte and can only be 0 or 1. The string is `u16 length |
UTF-8 bytes `; the variable byte string is ` u16 length | bytes `. All vectors are ` u16 count |
elements `; the length and count are only limited by the outer layer ` u16 body_length` (maximum
65535) and the actual carrier capacity. `NodeId` is the first 16 bytes of SHA-256 of the Ed25519
public key, transmitted on the wire as `bytes[16]`; it does not contain the text `n` prefix. The
public key, signature and CircuitId are `bytes[32]`, `bytes[64]` and `bytes[16]` respectively.

Reliable QUIC stream frames are all `message_type:u8 | body_length:u16 | body`. No magic, version or
reserved fields; unknown type, length mismatch, illegal boolean, truncation, vector/string beyond
remaining body are rejected. The maximum inter-node body size is 65535 bytes.

## Inter-node messages

| type | name | body |
| --- | --- | --- |
| 1 | Hello | `node_id | public_key | link_nonce:bytes[32] | signature` |
| 2 | HelloAck | `node_id | public_key | signature` |
| 16 | Open | `source | destination | ttl:u16 | circuit_id | ephemeral_public_key | open_nonce:bytes[16] | source_public_key | path_count:u16 | path | signature` |
| 17 | OpenAck | `circuit_id` |
| 18 | OpenReject | `circuit_id | retryable:u8 | reason_code:u16` |
| 19 | Ping | Empty |
| 20 | Pong | Empty |

The Hello signature input is a concatenation of the original fields in its body except signature;
HelloAck uses the same fields and appends the 32-byte nonce of the connection Hello. The OPEN
signature input is a concatenation of the original fields from source to path in the Open body. The
LSA signature input is all the fields before signature in the LSA below. There is no domain or
version prefix.

`OpenReject.reason_code`: 1 invalid_path, 2 ttl, 3 transit_denied, 4 unexpected_previous_hop, 5
replay, 6 capacity, 7 missing_next_hop, 8 manual_path_denied, 9 circuit_rebinding, 10
key_install_failed, 11 local_control_admission (relay local control flow temporary back pressure;
source shall not quarantine it as a candidate path failure).

## OPEN ECDH and DATA

Source generates a CircuitId and temporary X25519 key pair when creating an active Circuit for the
first time. OPEN signatures protect temporary public keys. After the destination verifies the OPEN,
path and policy, it calculates the shared secret with the static X25519 private key obtained by
Ed25519 conversion and the source temporary public key; both parties derive the DATA key in the
following way:

```text
HKDF-SHA256(
  salt = "tinect-payload-v3\\0",
  ikm = X25519(exit_static_private, source_ephemeral_public),
  info = source_ed25519_public | exit_ed25519_public | circuit_id | source_ephemeral_public
)
```

destination only sends OpenAck after successful installation of `(Link instance, CircuitId, source
public key, ephemeral public key, receiver session)`. Retry idempotent with the same CircuitId,
source key, and temporary public key without resetting the replay; rebind with any different fields
is rejected. Keys are not rotated within active Circuits; new CircuitIds/keys are created when Link
is reconnected, process restarted, or explicitly rebuilt.

INIT, SessionInit, SessionAck, epoch and DATAGRAM INIT are all deleted. The only circuit frames
allowed in physical forward are:

```text
circuit_id: bytes[16] | sequence:u64 | ciphertext_and_tag
```

The nonce is `0x00000000 | sequence`, the AAD is `circuit_id | sequence`, and the fixed overhead is
40 bytes. After reaching `u64::MAX`, the source stops the Circuit and reopens OPEN, never wrapping
around or reusing the nonce. Relay read-only CircuitId forwarding.

## Physical layer and topology

The physical DATAGRAM is `sequence:u64 | ciphertext_and_tag` with no version field. The nonce is
`0x00000000 | sequence`; when the serial number is exhausted, close and re-authentication Link. The
plain text is `payload_type:u8 | payload`: 1 Forward, 2 Topology.

Topology payload: `advertisement_count:u16 | advertisements`. Each LSA:

```text
origin: NodeId | sequence:u64 | expires_at:u64 |
neighbor_count:u16 | (node:NodeId | cost:u32 | datagram_mtu:u16)* |
origin_public_key:bytes[32] | signature:bytes[64]
```

`datagram_mtu` above is the historical field name; the current implementation maintains the field
position and width, but interprets it per RFC-0037 as `inner_mtu`, the full user IP packet capacity.
It does not represent Physical frame or QUIC application DATAGRAM capacity.

Only LSAs that pass the signature, origin, public key, timeliness, no loops, and monotonic sequence
can be propagated.

## Native Unix Management Protocol

Request: `opcode:u8 | body_length:u16 | body`. Response chunk: `opcode:u8 | status:u8 |
body_length:u16 | body`; the server continuously writes chunks and closes the connection after a
request, and EOF indicates the end. opcode: 1 state, 2 Routes, 3 Topology, 4 Pcap. status: 0
success, 1 invalid_request, 2 internal_error; error body is String. RFC-0027 removes the Reload
opcode and the runtime configuration remains immutable.

State body:`node_name:String | node_identity:Optional<NodeId> | links:Vec<LinkRecord> |
circuits:Vec<CircuitRecord> | flow_count:u64 | topology_nodes:u32 | topology_generation:u64 |
supervised_tasks:u32 | shutting_down:u8 | last_shutdown_error:Optional<String> |
circuit_traffic:Vec<TrafficRecord> | acl_rejections:Vec<RejectionRecord>`.

LinkRecord: `peer_name:String | peer_identity:String | healthy:u8 | last_error:Optional<String> |
metrics:Optional<LinkMetrics>`; LinkMetrics are encoded in Rust field declaration order,
`fec_enabled` is `u8`, `fec_repair_rate_milli` is `u16`, and the remaining capacity, count, and
local FEC metrics are all `u64`. LinkMetrics does not include Quinn's RTT, ACK loss, congestion
window, path MTU, or send buffer statistics. CircuitRecord:`destination:String |
destination_identity:Optional<String> | active_path:Vec<String> |
active_path_names:Vec<Optional<String>> | healthy:u8`. TrafficRecord:` name:String | tx_packets:u64 |
tx_bytes:u64 | rx_packets:u64 | rx_bytes:u64`. RejectionRecord: ` reason:String | count:u64`.
RouteRecord:`prefix:String | candidates:Vec<String>`. Topology response is `graphviz_dot:String`,
only as a local diagnostic view; PCAP body is standard PCAP v2.4 bytes.

## Security and Compatibility

There is no compatibility layer for this protocol; all interconnected nodes must be upgraded
simultaneously. Removing the signature domain is an explicit protocol decision, field layout and
validation context must still be strictly fixed by message type. The relay maintains opaque DATA
forwarding. All lengths are verified first to avoid unbounded allocation. JSON can continue to be
used for configuration or CLI presentation, but must not go into wire encoding or signed input.

## acceptance

Unit tests cover binary control frames, truncation/length/boolean rejection, OPEN signature field
tampering, ECDH DATA key, CircuitId isolation, sequence number exhaustion rejection, and binary
round-trip for managing state/routing; integration tests cover Hello, OPEN, three-node forwarding
and egress ACL. The implementation needs to pass fmt, clippy, cargo test, as well as the three-node
link establishment, binary LSA, forwarding convergence and resource cleanup verification of
`remote_auth_forwarding.sh` and `remote_multi_route.sh`.

## Implementation Notes

Implementation passed `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings ` and ` cargo test `. ` tests/remote_auth_forwarding.sh ` and ` tests/remote_multi_route.sh`
verify three-node link building, binary LSA, forwarding convergence and resource cleanup.
