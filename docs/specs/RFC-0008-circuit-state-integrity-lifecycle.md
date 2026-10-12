# RFC-0008: Circuit integrity, life cycle and continuous convergence

> RFC-0046 updates the control message fields of this article: CircuitId replaces Open nonce as
  the wire token, the signature is added to the message kind, and the long lease will not be
  revoked if the short-term Renew fails; when all feedback and Renew are lost, the source long
  lease-sized failure grace provides the final boundary. History of this article Lifecycle
  invariants still apply to parts of RFC-0046 that are not explicitly superseded.

- Status: Implemented
- Created: 2026-07-24
- Last updated: 2026-08-31
- Change record: 2026-08-31 Clarified that the data plane receiving task must listen for Link
  closure and exit in time to avoid holding the Link's internal Forward queue, resulting in the
  inability to release resources after closure; 2026-08-28 Change the CircuitId generation to a
  random 64-bit prefix plus a monotonic 64-bit counter to remove the historical ID set within the
  process life cycle; 2026-08-03 Added RFC-0022 Draft's ProofStale/HardRevoked life cycle boundary
  clearly does not change local immediate recycling invariants; 2026-08-27 updated control message
  fields, signature fields and Renew failure semantics by RFC-0046.

## Background and Goals

RFC-0007 eliminates deterministic labels, but Circuit's replay, rebind, recycling, and control
result authentication are still incomplete. This article defines verifiable circuit binding,
end-to-end control results, event-driven leases, and source persistence convergence. As long as the
destination is still required by the configuration and the topology has a valid path, the source
must not permanently stop establishing the circuit.

The goal is to eliminate the rebind of CircuitId on the same inbound link, control result forgery
and unbounded replay, and prevent link building after loss of connection from being permanently
stopped due to limited retries. This article does not provide legacy wire compatibility, nor does it
introduce key rotation or forward secrecy.

## design

Both the DATA and physical layers use a 65,536-bit sliding replay window: the maximum sequence
number for successful authentication is the right end of the window, the left side of the window and
the set sequence number are rejected. Each Circuit binding is uniquely determined by
`(incoming_link_instance, CircuitId)`, binding the source public key, temporary public key,
destination and path; exactly the same Open idempotent, any different fields are rebind and
rejected. CircuitId is the only wire token for a Circuit attempt: the source uses a random 64-bit
prefix generated when the process is started and a monotonic 64-bit counter to form an ID; node
restart is a state-free boundary that allows counting to be restarted, and there is no need to save
all historical IDs.

Circuit uses 12 hour leases. Close, link closure, route replacement and topology withdrawal are
recycled immediately; active DATA refresh deadline, idle source refresh every 6 hours. Expiration is
collected by the deadline/generation scheduled event of each binding instead of periodic scanning.

The source CircuitManager maintains a deduplication worker for each required destination. OPEN fails
with jitter index backoff, up to 5 seconds, and continues to retry until there is no valid path or
the destination is no longer needed. Renew is an independent low-latency confirmation/detection:
local admission backpressure, send timeout, ACK loss or duplicate ACK only updates `RenewPending`
and retains the active lease; the first consecutive failure starts a local failure grace equal to
the current long lease and is bound by `CircuitId + lease_epoch`. A successful and counter-matching
RenewAck clears it, clearing CircuitBroken, Link instance shutdown or grace/real lease expiration
before revoking and entering normal OPEN Rebuild. Candidate OPEN failures, candidate exhaustion, and
ACK timeouts in migrations must also go through the same grace check. When grace expires, complete
hard-revoke, clean up active, session, return-flow, Circuit DNS and authorization, and send
CircuitClose with best-effort. When there is no healthy circuit in the data plane, it is selected in
the order of remaining overlay, local fallback, and discard, and EnsureCircuit is performed
asynchronously.

### Lifecycle Boundaries with RFC-0022

RFC-0022 (currently Draft) specifically distinguishes the above "topology revocation and immediate
recycling" into two types of events: `ProofStale` that is still within the validity period but has
not yet received the refresh message does not revoke the existing lease and only allows the last
confirmed conservative sending budget to be used; proof of actual expiration, path edges being
explicitly removed, first-hop Link instance closing, and configuration changes that affect target
identity, ACL, path constraints or egress security semantics are all considered `HardRevoked`, the
active dataplane snapshot, authorization, and local sending qualifications must be revoked
immediately, and efforts must be made to send signature Close.

This clarification does not change the local immediate reclamation invariant of RFC-0008, nor does
it precondition the success of the remote Close for local cleanup. Before RFC-0022 is accepted and
implemented, the Implementation Notes and `docs/protocol.md` of this RFC are still subject to the
current lease/binding behavior; after acceptance, the alternative boundary of RFC-0022 should be
linked in the Implementation Notes.

## control message

All fields are RFC-0007 binary base types; the first field of each signed transcript is its own wire
kind, followed by the message's non-signed fields and the signing public key.

- Open: `kind:u8(16) | CircuitId | ephemeral_x25519[32] | source_public_key[32] | path_count:u16 |
  path | signature[64]`. The source is derived from the public key, and the destination is derived
  from the end of the path.
- OpenAck:`CircuitId | responder_public_key[32] | signature[64]`.
- OpenReject:`CircuitId | retryable:u8 | reason:u16 | responder_public_key[32] | signature[64]`.
- CircuitRenew:`CircuitId | counter:u64 | source_public_key[32] | signature[64]`.
- CircuitRenewAck:`CircuitId | counter:u64 | responder_public_key[32] | signature[64]`.
- CircuitClose:`CircuitId | counter:u64 | reason:u16 | source_public_key[32] | signature[64]`.
- CircuitBroken:`CircuitId | reason:u16 | reporting_public_key[32] | signature[64]`. This feedback
  is used uniformly for unknown sessions, relay label missing, Renew binding rejection and
  downstream link failure; the relay is verified and re-signed hop by hop along the old reverse
  path, and the source matches the CircuitId according to the current first hop Link instance.

ACK must be signed by exit; Reject must be signed by exit or the actual rejected path node. The
receiver verifies the current Link instance, CircuitId, role, and signature. Restarting does not
restore the Circuit; the new Link instance only accepts new CircuitId and new temporary keys.

## acceptance

Unit tests cover sliding windows, Open idempotent/rebind, result signing, Renew/Close, expiration
and Link-instance isolation. The remote three-node test covers restarting source/relay/exit, control
packet loss, continuous reconnection, old packet rejection and resource cleanup.

## Security and deployment implications

The control frame format changes and is not compatible with old nodes. The deployment must allow
nodes in the same interconnection domain to be upgraded at the same time. Signature verification
failure, CircuitId mismatch, and non-current Link instance results shall not change the source
active Circuit. Close must first verify the source identity, counter and signature before deleting
the authorization, receiving session and forwarding table; node restart or Link instance replacement
will not inherit the old state.

## Implementation Notes

This life cycle supplement binds failure grace to `CircuitId + lease_epoch`, and all migration
keepalive paths uniformly perform expiration checks; Renew waiter only accepts RenewAck of accurate
counter. Grace reuses the complete hard-revoke upon expiration, cleans up active, session,
return-flow, Circuit DNS and authorization, and sends CircuitClose with best-effort.

The current implementation has implemented 65,536 packets including the sliding replay window after
authentication, immutable binding keyed with `(Link instance, CircuitId)`, signature
OpenAck/OpenReject, signature CircuitClose hop-by-hop recycling, Link instance disconnection
recycling, and when the configuration or topology is revoked, the source actively closes and cancels
the active snapshot. OPEN wire only retains the CircuitId, temporary public key, source public key
and path. The source/destination is derived from the authentication field. All signature control
messages are separated by the kind field. Unknown sessions, missing relay labels, Renew binding
rejections and downstream link failures all go to CircuitBroken. The authenticated new Link instance
will atomically replace the old instance of the same peer to avoid the old QUIC refusing to restore
the connection during the idle timeout period after the node crashes; the cleanup of the old
instance is strictly isolated by instance. The source maintains a single worker's continuous OPEN
retry with jitter for each destination (5 seconds capped); active snapshot revocation, Link
creation/replacement, and verified topology updates all use algebraic notifications to wake up
workers. The 12-hour lease uses the minimum heap marked by generation and waits for a single recent
deadline regularly; authentication DATA and Renew refresh the deadline, and the binding,
authorization, receiving session and forwarding table will be accurately recycled when they expire.
Renew's instantaneous control admission/send/ACK failure retains the active lease and starts a local
failure grace bound by `CircuitId + lease_epoch` equal to the long lease; only a RenewAck that
matches the exact counter of the waiter can clear the grace. Migrate keepalives and active
keepalives to uniformly check grace, reuse the complete hard-revoke upon expiration, clean up
active, session, return-flow, Circuit DNS and authorization and send CircuitClose with best-effort,
and then enter reconstruction. The OPEN/RENEW waiter is additionally bound to the non-wire lifecycle
token corresponding to the Link; when the Link is closed or dropped, the token is revoked first, and
teardown will revoke and clean up the waiter and authorization again. ACK reviews the token in the
authorization lock, so there is no need to save the unbounded historical revoked-Link set.

Fault injection covers egress, relay and source in sequence without status restart, downstream link
packet loss, OPEN ACK timeout and re-forwarding after recovery. The lease expiration test verifies
that only the binding of the current generation is deleted, the authorization is revoked and
subsequent Renew is rejected; the instant deletion of the receiver session is also independently
tested. The signature and monotonicity of Renew/Close are covered by control plane unit tests.
Implementation and acceptance are complete.

2026-08-31 Added data plane receiving boundary: `receive_secure_link` while waiting for the Forward
queue and Link closing events; the receiving task must exit when the Link is closed, even if the
Link itself still holds the queue sender. The Linux privilege coverage test verifies unknown
sessions, authorization frames, and rejected paths before closing the Link, and both the receiving
task and the dispatcher exit within the bounded time; the complete coverage command passes within
the isolated network namespace.
