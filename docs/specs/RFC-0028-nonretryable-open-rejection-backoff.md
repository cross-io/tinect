# RFC-0028: Stable backoff for non-retryable OPEN rejections

- Number: RFC-0028
- Status: Implemented
- Created: 2026-08-10
- Last updated: 2026-08-27

> RFC-0046 updates the wire field and signature field of OpenReject; this RFC still defines the
  CircuitIdentity backoff and path change wake-up semantics of `retryable=false`.

## background

The source maintains a persistent OPEN worker for each destination. After the topology Delta is
accepted, the reconciler will be awakened so that the new path, first-hop link or capacity can take
effect immediately. Previously, if the remote end returned the signed `OpenReject { retryable: false
}` for the same candidate path, each Delta that was not related to the path would end the worker's
backoff early and immediately send OPEN again. Periodic advertising during the link startup phase
thus generates high frequency control frames, logging, context switches, and unnecessary CPU
consumption.

## Goals and Non-goals

The goal is to preserve the existing exponential backoff with jitter on the same rejected path while
preserving fast convergence when the path actually changes. Non-goals are recovery strategies that
do not change OpenReject's retryable/rejection code semantics or retryable=true; its current wire
format and signature fields are specified by RFC-0046.

## design

After receiving `retryable=false`, the worker records:

```text
(CircuitIdentity, retry_not_before)
```

`retry_not_before` uses existing per-destination exponential backoff (capped at five seconds). When
the next parsing result is still the same `CircuitIdentity`, even if a topology/reconcile
notification is received, the state will only be rechecked and wait for the original deadline; OPEN
will not be sent again. If the path, destination, or first-hop Link instance changes, the record is
immediately cleared, the backoff is reset, and new candidates are tried. After the deadline is
reached, the next OPEN is still initiated for the same identity.

This ensures that "non-retryable" will suppress busy loops on the same context, but will not turn a
temporary remote status into a permanent deny.

## Security and Compatibility

Does not modify current wire data, authentication, authorization, or data plane sending
qualifications. Rejections must still be RFC-0046 signed and verified by the Link instance before
affecting workers. The delay only applies to source OPENs that have not yet been established; the
semantics of HardRevoked, Link close, and configuration revocation of existing leases remain
unchanged.

## Testing and Acceptance

Unit tests cover non-retryable reject hold backoff for the same `CircuitIdentity`, as well as first
hop or path change clear backoff. Rust checks and network integration scenarios verify that
intensive OPEN retries are not triggered by duplicate topology notifications during rejection of the
same path.

## Implementation Notes

2026-08-10: Implement the non-retry rejection deadline maintenance for the same path; changes to the
path or first-hop instance will immediately lift the restriction.
