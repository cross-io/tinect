# RFC-0042: bounded service task life cycle

- Number: RFC-0042
- Status: Implemented
- Created: 2026-08-23
- Last updated: 2026-08-23

## Background and Problem

FakeIP DNS, metrics, and the native management interface all use `JoinSet` to track request tasks.
Concurrent semaphore limits the number of tasks running at the same time, but if the completed tasks
are only in the shutdown phase `join`, their completion records will still be accumulated along with
the process. Therefore "concurrency bounded" does not equal "long-term memory bounded". The unified
daemon supervisor will also receive a small amount of short-life cycle work and has the same
completion record retention problem.

FakeIP DNS's TCP connection can also permanently occupy the permit without sending a complete
request. After either UDP or TCP listener exits abnormally, the other sibling listener must also be
canceled and waited, and cannot leave the service owner.

## Goals and Non-goals

Target:

- Completed request tasks are recycled in a timely manner while the service is running, and the
  retained task records are constrained by the current concurrency.
- Supervisor recycles completed records when registering new tasks to avoid infinite growth of
  short task history.
- The supervisor's active count can also be recycled when the task panics, and join failure is
  reported during shutdown.
- Set fixed deadlines for FakeIP TCP DNS request reads, processing, and response writes.
- Place FakeIP UDP/TCP listeners in the same subcancellation domain; cancel when either listener
  ends and wait for the other.
- Clean up single-flight registrations when a query is canceled without breaking serial merges of
  the same query.
- Circuit DNS query future immediately deletes its response associated token when it is canceled.
- The semantics of waiting for all still running subtasks during shutdown are maintained.

Non-goals:

- No changes to DNS wire format, caching, FakeIP address allocation, or upstream selection
  semantics.
- Does not change Circuit, Link or control message lifecycle.
- No configurable items are added; the fixed deadline belongs to the native resource protection
  boundary.

## design

### Recycling completed during runtime

The long-term listener's `select` is waiting for cancellation, next connection/message and
`JoinSet::join_next()` simultaneously. As long as a subtask is completed, the completion record will
be consumed immediately; after cancellation, it will continue to wait for the remaining tasks to
complete.

The task set of `DaemonSupervisor` uses non-blocking `try_join_next()` to recycle completed tasks
before each registration. Supervisor mainly owns long-term tasks; the dynamically created jobs may
themselves have service admission or configuration scale upper limit, so the residual records after
stopping creation are at most equal to the number of tasks still being executed concurrently at that
time, and all will be joined during unified shutdown.

The active task count is held by the RAII guard inside the task, and will be decremented by normal
return, cancellation and panic unwind. Both runtime recycling and shutdown check `JoinError`; if
shutdown sees panic/cancel failure, it will return an error for daemon state to record, instead of
disguising the failure as a clean shutdown.

### FakeIP TCP deadline

The length and body reading of each TCP DNS frame must be completed within 10 seconds; the upstream
parsing and response writing must be completed within 30 seconds. The TCP connection is closed upon
timeout and the shared permit is released. A connection can still process multiple requests
sequentially, and each frame re-obtains an independent deadline.

### Listener ownership

FakeIP DNS creates child cancellation tokens for UDP/TCP listeners. After the parent service
receives cancellation or any listener returns, it cancels the child token and joins the two
listeners. The listener internally stops receiving when it sees the child cancels, and then joins
the admitted request task. Errors are returned based on the first listener result.

### Single-flight cancel security

Each participant of the same DNS query holds an RAII registration. When the last participant
(including those canceled while waiting for a lock) leaves, the registration is deleted only if the
map still points to the same lock and there are no guards, waiters, or other participants. Such
cancellation does not leave a map that grows forever by domain name, nor does it create a second
parallel upstream query for the same key while the old waiter has not yet completed.

DNS requests carried within the Circuit hold independent RAII registrations after inserting the
pending token. Normal responses, errors, timeouts, failure to send, and futures canceled by the
upper layer will idempotent delete the token. Late responses can only get deterministic
unknown/expired results, and the correlation map cannot be allowed to grow according to the number
of cancellations.

## Security and Compatibility impact

- on the wire protocol and authorization boundaries remain unchanged.
- TCP DNS clients that are slow or unresponsive will be actively disconnected to avoid exhausting
  all admission slots.
- Listener failure does not leave orphan tasks that still hold sockets, runtimes, or upstream
  senders.
- Task completion records no longer grow linearly with the total number of historical requests.

## Migration and deployment

No configuration migration or simultaneous upgrade of multiple nodes is required. The timeout only
works on the native FakeIP DNS TCP frontend.

## Testing and Acceptance Criteria

- The request listener can recycle completed subtasks during runtime, and the JoinSet will be
  empty after cancellation.
- Idle or incomplete TCP DNS frame releases connection task after deadline.
- The end of the sibling listener will cancel the other listener and wait for its cleanup to
  complete.
- The single-flight registration is automatically cleared after canceling a query that is waiting
  for upstream.
- After canceling the Circuit DNS query future, its pending token will be automatically cleared.
- After the supervisor dynamic short task is completed, the completion record will be recycled
  during subsequent registration.
- A supervisor task panic will not leak the active count, and a shutdown will report the failure.
- Via `cargo fmt --check`, full-featured Clippy and `cargo test`.

## open issues

none.

## Implementation Notes

- `src/fake_ip.rs`: DNS listener ownership, runtime recycling, and TCP deadline.
- `src/dataplane/route.rs`: Unregistered security of Circuit DNS pending token.
- `src/status.rs`, `src/status/management.rs`: Request task runtime recycling.
- `src/runtime.rs`: supervisor completed record recycling.
