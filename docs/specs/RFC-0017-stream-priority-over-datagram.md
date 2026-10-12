# RFC-0017: stream-priority-over-datagram

- Number: RFC-0017
- Title: stream-priority-over-datagram
- Status: Implemented
- Created: 2026-07-27
- Last updated: 2026-08-24
- Change record: 2026-07-27 First draft - Define the sending priority, reserved capacity and
  unified behavior of various carriers for reliable streams versus unreliable datagrams.
  2026-07-30 Updated the Reliable TopologySync service to RFC-0016, removed the outdated Physical
  Topology D1 semantics, and made it clear that this RFC only guarantees the connection local
  admission order. 2026-07-31 Clarify the S0 failure boundary, the priority of S1 to D0, and all
  outbound entries must go through the arbiter; the arbiter is created during the connection life
  cycle to cover Hello/HelloAck, and increases the bounded progress rules of S1. Fixed the
  arbiter's guaranteed bounds for local queue admission and does not declare the asynchronous
  carrier API or line delivery order. 2026-07-31 Implement per-Link local admission gate, S0/S1
  bounded fairness, stream bounded yield to datagram, write concurrency upper limit and rejection
  count, and complete real mixed-carrier verification. 2026-08-24 Add a unique ticket to the
  pending stream and cancel safe recycling; when timeout/Link closure causes the admission future
  to be discarded, precisely delete its pending or granted items and byte budget.

## Background and Problem

Tinect currently uses the same QUIC connection for two types of transmission at the same time:
control plane uses QUIC stream, Physical Forward, Topology and PMTU use QUIC DATAGRAM. RFC-0014 adds
"QUIC stream + bare UDP Physical frame" and fake-TCP outer layer, so the same logical Link may have
four carrier combinations:

1. QUIC stream + QUIC DATAGRAM over UDP;
2. QUIC stream + bare UDP Physical frame over UDP;
3. QUIC stream + QUIC DATAGRAM over fake TCP;
4. QUIC stream + bare UDP Physical frame over fake TCP.

Currently, `send_control()` will directly create the stream, and the data plane can continuously
call `send_physical()`. During egress high throughput, relay forwarding, or topology flooding,
datagram sending may fill up Quinn's congestion window, send buffer, or underlying socket, causing
the following problems:

- The delay in establishing or repairing circuits with control messages such as OPEN, OPEN_ACK,
  CLOSE, RENEW, PING/PONG, etc. increases;
- The stream's reliable retransmission competes with the datagram's discardable traffic for the
  same underlay;
- When the outer layer of fake-TCP generates a large number of PSH|ACK packets, the pressure on
  the middlebox, RST guard and kernel queue is amplified;
- Bare UDP does not have Quinn's congestion control, and the datagram may in turn suppress the
  QUIC stream on the same endpoint;
- Mistaking "Send API successfully" as "High priority control message has been given a chance to
  be transmitted".

The stream here refers to the reliable, ordered byte stream of QUIC, excluding the shape of
fake-TCP; the datagram refers to the Physical frame carried in QUIC DATAGRAM or bare UDP/fake-TCP.
The priority must be consistent across carriers, and fake-TCP cannot be regarded as a reliable TCP
data stream just because the outer layer looks like TCP.

## Goals and Non-goals

Target:

- In each connection/peer arbitration domain, the stream to be sent is given priority to get the
  opportunity to send when competition occurs;
- In times of high datagram load, link packet loss and PMTU changes, priority is given to
  completing the limited messages of the control plane;
- Unify the scheduling semantics of the four RFC-0014 carriers and clarify the processing method
  of the real TCP/UDP inner flow;
- Maintain the low-latency, discardable semantics of datagrams without queuing to disguise them as
  reliable transmission;
- No new congestion control, pacing, fixed rate or normal datagram quotas will be added, and the
  peak speed without competition will not be reduced;
- Make queue capping, drops, starvation, and priority preemption have observable consequences;
- Existing wire frame, Physical AEAD, QUIC TLS, circuit encryption, and relay plaintext boundaries
  are not changed.

Non-goals:

- Does not modify the standard congestion control, retransmission, and ordering semantics of QUIC,
  UDP, TCP, or fake-TCP;
- Does not introduce QUIC/underlay-independent congestion control, pacing, rate shaping, or
  persistent datagram budgeting;
- There is no guarantee that the stream will be delivered in time when the underlay is completely
  interrupted, the peer stops reading, or the congestion window reaches zero;
- Does not change the Physical Forward from datagram to stream, nor automatically retransmits lost
  datagrams;
- Do not give different physical reliability according to the TCP/UDP protocol number of the
  user's inner IP packet;
- Ordinary data flows are not allowed to preempt the minimum control resources required for
  identity handshaking, protocol parsing, or security verification.

## Terminology and Priority Model

- **stream traffic**: control messages and future protocol messages explicitly registered as
  reliable streams.
- **datagram traffic**: Physical Forward, PMTU Probe/ProbeAck, and future messages registered as
  unreliable Physical form. RFC-0016's TopologySync does not belong to datagram traffic.
- **stream opportunity**: The next local admission decision is temporarily reserved while the
  stream is waiting: the stream message is handed over to the bounded writer, but the non-datagram
  is handed over to the datagram scheduler. It is not a byte quota, rate quota, or congestion
  window, nor does it mean that `open_uni`, socket send, or line send has occurred.
- **bulk datagram**: Forward traffic encapsulated by inner IP data packet.
- **maintenance datagram**: Non-user datagrams such as PMTU and link health. It is still
  unreliable, but cannot use the same lowest priority as bulk datagram.
- **admission**: Queuing and budget checking before messages enter the carrier write path; not
  QUIC's wire priority extension.

The priority from high to low is fixed as:

| Level | Traffic | Purpose | Default Drop Policy |
| --- | --- | --- | --- |
| S0 | Identity/control messages for QUIC stream | Link establishment, OPEN/ACK/REJECT, CLOSE/RENEW, PING/PONG | MUST NOT be discarded locally due to D0/D1/D2 contention; may still fail due to Link, protocol, flow control or carrier errors |
| S1 | Low-frequency maintenance messages registered on stream | RFC-0016 TopologySync, future reliable maintenance messages | Must not be blocked by D0/D1/D2, and will be processed by the protocol itself after timeout |
| D0 | PMTU Probe/ProbeAck | Recovery capacity and black hole detection | Can be retried but not allowed to enter the normal datagram queue |
| D1 | Other maintenance datagram | Link health and unreliable maintenance traffic explicitly registered in the future | Can be merged or discarded, cannot be backlogged indefinitely |
| D2 | bulk Forward | User data plane | Discard latest or oldest item when queue is full, selected by implementation but must be observable |

The "high priority" of S0/S1 indicates the priority of the local admission and writer queues, and
does not mean that the underlay's RTT, congestion window, kernel queue or peer receive window can be
bypassed. The priority is not strict priority: when S0/S1 has a message to be sent, the arbiter will
give priority to the stream to the writer at the next schedulable boundary, rather than the
admission datagram, but the bounded fair concession in this article must be followed; arbitration
will be re-arbitrated immediately after the handover. When there is no stream to send, the datagram
is not subject to the additional rate or capacity limitations of RFC-0017. This RFC does not
guarantee strict sending order for Quinn `open_*`/write calls, kernel sockets, fake-TCP, or
underlays.

## design

### Unified connection sending arbitration

Each QUIC connection/peer transport context adds a lightweight send arbiter when it is created, and
binds it to a logical Link after authentication is completed. Hello/HelloAck, subsequent control
stream, TopologySync, PMTU and Physical datagram must pass through the same arbiter. This arbiter
only deals with "who gets the next sending opportunity first" and does not maintain new congestion
windows, rate estimates or long-term budgets. It is isolated by connection/peer rather than shared
by the entire UDP socket: one socket can carry multiple QUIC connections; for the raw UDP Physical
path of RFC-0014, the raw UDP sending entry of the same peer must also be bound to the connection
arbiter:

```text
S0/S1 stream admission
          │
          ├── stream writer(s)
          │
          └── datagram scheduler
                ├── D0 PMTU
                ├── D1 maintenance datagram
                └── D2 bulk Forward
```

The arbiter must satisfy the following invariants:

1. When S0/S1 is already waiting for local admission, the scheduler gives priority to suspending
   new D0/D1/D2 admission and hands over a stream message to the bounded writer; only when the
   bounded fair yield threshold is reached, a datagram admission is allowed. This does not form a
   persistent datagram rate cap, nor does it guarantee that the writer has called `open_bi`,
   `open_uni`, or actually written to the carrier.
2. D0 is only allowed to complete the ongoing PMTU detection, and D1 is only allowed to send the
   latest maintenance message that has been merged; the original datagram sending path is
   restored immediately after the stream writing is completed or fails.
3. Stream writing is only performed after the message encoding is completed, and data plane locks
   cannot be held to wait for the network; stream admission can only hand over the message to the
   bounded writer non-blockingly, and the arbitration permit must not be held across `open_bi`,
   `open_uni`, write, flow-control or other networks. The completion of the handover constitutes
   the stream priority guarantee of this RFC, and must be re-arbitrated immediately thereafter;
   datagram encryption, physical sequence allocation and actual sending cannot block the control
   handler either.
4. Stream messages are not queued in the datagram queue, and datagram is not converted to stream
   because it is waiting for stream.
5. A single D2 packet occupies at most one scheduling round; other levels must not be blocked by
   a large packet, a slow receiver, or a relay subscriber.
6. The existing protocol order is maintained within the same priority: messages of the same
   control stream are in stream order; the Physical frame continues to share the
   `physical_sequence` and replay window of RFC-0015.
7. S0/S1 is not a strict priority: when the two continue to compete, the arbiter can admit at
   most `MAX_CONSECUTIVE_S0_ADMISSIONS = 8` consecutive S0s, and then must admit a waiting S1; if
   there is no waiting S1, S0 can continue. When any D0/D1/D2 is waiting, the arbiter can
   continuously admit `MAX_CONSECUTIVE_STREAM_ADMISSIONS = 8` S0/S1 at most, and then must admit
   a datagram selected in the order of D0, D1, and D2; if there is no waiting datagram, the
   stream can continue.

Implementations can use mutex, notify, or explicit queues, but the default policy must be "give on
demand" rather than quota scheduling:

- Does not use token buckets, fixed byte budgets, fixed packet rates, or long-term reserves
  calculated by RTT/cwnd;
- D2 still uses the existing memory safe queue upper limit, but this upper limit must not be used
  as a normal throughput limit, nor must it be adjusted lower due to RFC-0017;
- S0/S1 is checked before each datagram admission. Unchecked datagrams cannot be admitted in
  batches when there are already streams waiting for local admission;
- Wake up the datagram path immediately when S0/S1 transmission is completed, fails, or the
  connection is closed;
- When S0/S1 admission future is canceled, its own queuing ticket must be canceled accurately; it
  must not leave behind the number of messages, byte budget, or unconsumed grant, nor may it
  accidentally delete another waiter of the same level;
- D1/D0 cannot create unlimited tasks and must be implemented through merging, deduplication or a
  separate state machine.

RFC-0017 does not define new `reserve_bytes` configuration. Implementations MAY retain existing
queue caps to prevent memory exhaustion, but MUST not interpret the caps as link capacity,
congestion windows, or peak rates. Peak throughput should continue to be determined by QUIC, bare
UDP, fake-TCP, kernel sockets, and the peer's actual congestion/reception capabilities.

### Stream organization and fairness

Quinn is still responsible for reliable transmission between QUIC streams. The Tinect side must
avoid unlimited concurrency `open_uni()` for each control message, but should adopt a limited stream
writer concurrency upper limit; otherwise the stream itself will also cause queue head and memory
pressure. The protocol semantics of control messages continue to be defined by RFC-0007 and the
control encoding. The number of writers, queued messages, and queued bytes of S0/S1 must each have a
fixed upper limit per connection, and the failure result when full is defined; S0 must not be
discarded locally due to D0/D1/D2 competition, but can still fail due to its own upper limit,
connection closure, protocol error, or carrier error. The TopologySync stream cap of RFC-0016 is
part of S1 and does not replace the cap of S0.

This RFC specifies the following default upper bounds; implementations may use compile-time
constants, but must not let the remote end or configuration expand their meaning:

```text
MAX_S0_STREAM_WRITERS_PER_CONNECTION  = 8
MAX_S0_PENDING_MESSAGES_PER_CONNECTION = 256
MAX_S0_PENDING_BYTES_PER_CONNECTION    = 1 MiB
MAX_S1_STREAM_WRITERS_PER_CONNECTION  = 33
MAX_S1_PENDING_MESSAGES_PER_CONNECTION = 4096
MAX_S1_PENDING_BYTES_PER_CONNECTION    = 4 MiB
```

Calls that exceed the pending upper limit of S0/S1 must immediately return an observable
`admission_rejected` result and cannot wait indefinitely or be silently discarded; the caller will
then handle it according to the retry/backoff semantics of the protocol to which it belongs. A call
that has obtained Gate admission but is waiting for a peer writer slot must not fail directly with
`try_acquire`: it should wait for a bounded writer slot until the send is complete, the link is
closed, or the caller times out. RFC-0016's finer caps on normal TopologySync, recovery stream, and
pending Delta continue to apply concurrently. Of the 33 S1 writers, up to 32 can be used for all
non-recovery S1 jobs (including normal TopologySync), and 1 is only for RFC-0016 ACK/Request
recovery; any non-recovery S1 job must not occupy the recovery slot when it reaches its upper limit.
In addition to this retention rule, new jobs must be rejected the first time either limit is
reached.

An implementation can establish a dedicated control writer for S0 messages and a maintenance writer
for S1 messages; if the Quinn version or API does not support reliable stream priority, the priority
field cannot be pretended to be written to the QUIC wire, and the above-mentioned local admission
priority must be implemented through local writer admission. The S0 writer must not wait for the
D1/D2 queue to be cleared; S1 can give up the opportunity when S0 has pending messages, but it must
meet the above continuous S0 upper limit. When there is no stream waiting, the writer must not
periodically preempt datagrams, nor must it actively reduce the datagram emission rate in order to
"preserve priority".

Control plane retries still follow the nonce, epoch, idempotent and backoff rules of the message
itself. Raising stream priority does not increase OPEN reinstalls, late ACK mismatches, or replay
window consumption; queue wait time must be factored into the caller's timeout budget.

### Datagram classification and scheduling

#### D0:PMTU

PMTU Probe/ProbeAck uses an independent state machine defined by RFC-0014/RFC-0015. They do not
wait for the ordinary Forward queue, nor should they be flooded by ordinary Forward; but when S0/S1
has a message to send, in addition to reaching the mandatory fair yield threshold of
`MAX_CONSECUTIVE_STREAM_ADMISSIONS`, D0 must give up new probe sending opportunities. The sent Probe
is not retransmitted as a stream, and the ProbeAck is still only confirmed based on the probe ID and
target length. Forged ACKs must not change the capacity.

#### D1: Other maintenance datagram

D1 only applies to maintained datagrams that are explicitly registered as unreliable. Each D1
message must have merge, overwrite, discard, and retry semantics defined in the corresponding RFC;
D1 MUST NOT host RFC-0016's TopologySync. Except when the mandatory fair yield threshold of
`MAX_CONSECUTIVE_STREAM_ADMISSIONS` is reached, D1's transmission must not occupy the waiting stream
transmission opportunity, nor must it be delayed indefinitely due to D2 queue congestion; if the
control message is establishing/repairing the circuit, D1 gives up the current transmission
opportunity.

#### D2:bulk Forward

D2 is the lowest priority. TUN readers, egress sender workers, and relay workers must return/discard
quickly when admission fails and must not wait for stream opportunities synchronously. Packets that
have entered QUIC DATAGRAM are still processed by Quinn according to its DATAGRAM semantics; packets
that have entered bare UDP or fake-TCP sockets cannot be withdrawn, so priority arbitration must
occur before `send_physical()`.

The relay must not generate unbounded outbound D2 backlogs due to inbound D2 traffic. The outbound
connection/peer arbiter is executed independently, and relay forwarding cannot bypass S0/S1's send
opportunity arbitration. RFC-0015's ciphertext is transported as-is and relayed without decryption
and is not affected.

## Behavior of each carrier and protocol

| carrier/protocol | stream path | datagram path | RFC-0017 specific requirements |
| --- | --- | --- | --- |
| QUIC over UDP | QUIC reliable stream, shared connection CC | QUIC DATAGRAM, shared connection/path | Do on-demand admission before calling Quinn API; completely use the existing DATAGRAM sending path when there is no stream waiting |
| QUIC + bare UDP | QUIC stream goes Quinn; bare Physical goes shared underlay endpoint | bare UDP Physical frame | Two paths share connection/peer quorum; only let bare datagram give way while stream is waiting; QUIC stream reliability does not extend to bare Physical |
| QUIC over fake-TCP | QUIC stream is still a Quinn stream in the end | Each QUIC UDP-shaped datagram is encapsulated by fake-TCP | Fake-TCP's TCP sequence/ACK only serves shape and recovery, and does not change the D2 level; PSH|ACK must not be treated as a preemptible stream, and pacing must not be added |
| QUIC + bare UDP over fake-TCP | Same as above | Bare Physical logical packets are sent through fake-TCP outer layer | Scheduled according to logical datagram classification; fake-TCP RST guard, handshake recovery and resource restrictions still follow RFC-0010/RFC-0013 |
| inner IPv4 TCP | The outer layer is still D2, and the inner TCP itself is reliable | The outer layer is still D2 | It is not promoted to S0 because the inner TCP is reliable; packet loss is handled by the inner TCP to avoid double reliable queues and congestion control |
| inner IPv4 UDP | Outer D2 | Outer D2 | Maintain best-effort, discardable semantics; do not lower S0 for inner UDP, nor add retransmissions to it |
| Future non-QUIC carrier | Depends on carrier capabilities | Depends on carrier capabilities | Must implement the same admission/retention contract first; cannot use "outer layer is TCP/UDP" to derive priority |

When stream and datagram use different sockets (the bare carrier of RFC-0014), the arbiter must
still be located at the common connection/peer sending entrance of both; different sockets cannot be
considered to mean that there is no need for priority. If the operating system cannot provide an
accurate status for the share, use the existing memory safety queue upper limit and make it clear in
the status that the upper limit is not a throughput quota.

The arbiter must precede all outbound entries for this connection/peer; any path that bypasses it
and directly calls the Quinn `open_bi`/`open_uni`, `send_datagram`, bare UDP `socket.send`, or
fake-TCP send interface violates this RFC. The constraints include Hello/HelloAck, control messages,
TopologySync, PMTU workers, TUN/egress workers, and relay forwarding paths. Fairness between
different connections, socket-level queue isolation, and global admissions are not part of this RFC
and must be handled by independent endpoint resource restrictions.

## Protocol/data format

This RFC does not add an on the wire field and does not change the QUIC stream, QUIC DATAGRAM,
Physical form or fake-TCP message format. Priority is a local scheduling property and cannot be
requested by an unauthenticated peer on the wire to increase its own message level.

If a new stream or physical form is introduced in the future, it must be registered in the
corresponding RFC:

- Level (S0/S1/D0/D1/D2); TopologySync of RFC-0016 is fixed to S1;
- Whether to allow merging, discarding or retrying;
- Maximum message size and queue budget;
- Whether to rely on the authentication and replay semantics of RFC-0001/RFC-0007.

Unregistered stream messages must be processed as S1, and unregistered datagram forms must be
processed as D2 and unknown/illegal forms rejected; S0 or D0 permissions cannot be obtained by
default.

## Security and Compatibility impact

Priority itself is not an authentication mechanism and cannot bypass `EgressPolicy::authorize()`,
circuit binding, Physical AEAD, or end-to-end AEAD. The peer cannot consume the stream opportunity
by forging control messages, forging forms, or raising local queue requests; messages must still
first complete existing identity, signature, replay, and ACL checks.

Yielding on demand will only delay D2 during the short window when the stream has messages to send,
and should not reduce the peak throughput without controlled contention; it may give up a small
number of sending opportunities for the short-term throughput of the datagram under extreme mixed
loads. Implementations MUST limit the number of bytes of outgoing datagrams per connection, per
peer, and globally to avoid running out of memory through large volumes of authenticated but
invalid/unauthorized traffic. The control stream must also have a message size and concurrency upper
limit, and cannot become an infinite queue due to "high priority".

Compatibility is divided into two levels:

- on the wire format compatibility: since there are no wire changes, the old node can parse
  existing messages that the new node has sent;
- Compatible behavior: Old nodes do not give way on demand and stream priority cannot be
  guaranteed. If the deployment must rely on this guarantee, RFC-0017 must be marked as a
  capability requirement and the interconnected nodes must be upgraded as a whole. Single-end
  local scheduling results cannot be regarded as end-to-end guarantees.

QUIC's congestion control, stream flow control, DATAGRAM discarding and fake-TCP outer layer failure
may still cause S0 to be delayed or failed; indicators and state must distinguish between "local
queue waiting", "carrier admission rejection" and "underlay/QUIC transmission failure".

## Migration and deployment

Implement deployment in three phases:

1. **Observation phase**: Record stream waiting, D2 discarding, queue depth at each level, and
   carrier failure reasons. By default, the existing datagram budget will not be changed.
2. **Local Scheduling Phase**: Enables per-connection/peer on-demand stream yield, D0/D1
   independent queues, and existing D2 bounded admission; no changes to configuration format or
   wire format.
3. **Capability convergence stage**: RFC-0017 support can be reported in state/Diagnostics; only
   after all peers that require strict behavior guarantees are supported, "stream priority
   required" will be used as a deployment strategy.

During the upgrade, nodes that support RFC-0017 should still give priority to sending their own
streams, but it must be assumed that the old peer's datagram may continue to occupy its local
resources; this must not change the circuit status or misjudge that the peer is unreachable.
Rollback simply turns off the local quorum policy and does not involve database, key, or wire
migration.

## Observability

At least add or clarify the following connection/Link-level indicator/log fields, and dynamic text
must follow existing Prometheus label escaping rules:

- `stream_admission_wait_total`,`stream_admission_fail_total`;
- `stream_queue_depth`,`stream_yield_events_total`;
- `datagram_queue_depth{class}`,`datagram_queue_drops{class,reason}`;
- `priority_preemptions_total{from,to}`;
- Count/histogram of `priority_wait_seconds{class}`;
- send result:`admission_rejected`,`carrier_rejected`,`underlay_failed`.

Existing `datagram_queue_drops`, `forward_queue_drops`, and QUIC path indicators MUST NOT be
deleted; implementations should indicate whether they are before or after the new arbiter to avoid
the same drop being counted twice.

## Testing and Acceptance Criteria

Unit and component tests cover at least:

1. S0 can still preferentially enter the stream writer when D2 continues to flood; except when
   the bounded fair concession threshold is reached, D2 cannot continue to obtain datagram
   admission when S0 is already waiting for local admission.
2. After S0/S1 arrives, the new D0/D1/D2 admission will be suspended first; when the bounded fair
   yield threshold is reached, a datagram admission will be resumed. There is no infinite hunger
   in S0/S1 and datagram.
3. The rank order, sibling order, queue upper limit, merge and drop reasons of S1, D0, D1 and D2
   can be asserted; TopologySync does not enter the datagram queue.
4. QUIC DATAGRAM oversize, send buffer full, bare UDP PMTU limit, and fake-TCP encapsulation
   failure are counted separately and do not change the reliability or control nonce/epoch of the
   stream.
5. Both inbound and outbound relay pass through the arbiter; relay does not decrypt or rewrite
   RFC-0015 ciphertext, and does not block the control stream due to D2 backlog.
6. Both inner TCP and inner UDP maintain D2 semantics; escaping to S0 based on the inner IP
   protocol number is prohibited.
7. Under link shutdown, concurrent dial replacement, task cancellation, and backpressure, all
   queue statuses, queues, and counters can be released without leaking tasks or memory.
8. When multiple threads concurrently call `send_control`/S1/D0/D1/D2, physical sequence, control
   message sequence and stream yield status will not cause a race condition.
9. All four RFC-0014 carriers meet the same local admission contract in simulated testing; Linux
   CI does at least one real fake-TCP and bare UDP high load test and confirms RST guard, TUN,
   routing, namespace and firewall resource cleanup.
10. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and
    `cargo test`; update configuration, schema, and observability documentation as needed after
    implementing RFC-0017.
11. Hello/HelloAck has passed through the connection arbiter before the logical link is created;
    other connections on the same UDP socket will not be mistaken for the same arbitration
    domain.
12. When S0/S1 continues to compete, S1 will get at least one opportunity every
    `MAX_CONSECUTIVE_S0_ADMISSIONS + 1` stream admissions; when there is continuous stream
    competition, datagram will get at least one opportunity every
    `MAX_CONSECUTIVE_STREAM_ADMISSIONS + 1` admissions; the reason for the failure of S0/S1's
    own queue being full can be asserted and observed.
13. Writers blocked by peer stream credit or write backpressure do not hold arbitration permits;
    the remaining levels continue to obtain admission according to bounded fairness rules.

The minimum criterion for successful acceptance is: under conditions of D2 saturation and
recoverable packet loss, the control stream can enter the bounded writer first, and S0 messages will
not be queued behind the infinitely growing D2 local admission queue; when there is no stream
competition, D2's sending path and peak rate are not additionally restricted due to RFC-0017. This
criterion does not treat the writer's asynchronous carrier call order or wire dispatch order as a
guaranteed result.

## Open Questions

- Specific implementations of stream concessions can be connection/peer admission before sending
  API calls, scheduling boundaries after a single datagram, or equivalent mechanisms;
  implementations must be able to test the order of "handover to writers relative to datagram
  admission" and must not claim asynchronous carrier API call order or line-level order as a
  guarantee of this RFC.
- Whether to create a separate QUIC stream for S1 maintenance messages, and the extent to which
  stream priority is controllable by the current version of Quinn, need to be confirmed at the
  implementation stage; if it is not controllable, continue to use local writer admission.
- RFC-0017 itself does not require Hello capability; only when a certain deployment strategy
  requires end-to-end local scheduling capability guarantee, capability negotiation will be added
  to the corresponding deployment RFC.
- When bare UDP does not share congestion control with QUIC, the need for an independent failsafe
  upper limit can still be discussed in RFC-0014; if introduced, this upper limit must prove to be
  a safe threshold to prevent abnormal flooding, rather than the normal rate control of RFC-0017.

## Implementation Notes

Implemented. `priority::Gate` is the local admission arbiter of each link: the waiting queues of S0
and S1 are limited to 256/1 MiB and 4096/4 MiB in the number of messages and encoded bytes. S1 must
be given a chance after 8 consecutive S0 admissions; waiting D0/D1/D2 must be given a chance after 8
consecutive stream admissions. Datagram admission is non-blocking and is rejected when it cannot
immediately enter the local writer path without occupying the stream task.

`Link::send_control()` classifies topology messages as S1, and other control messages as S0; Gate
admission and writer slot waiting can be canceled by connection close; control messages that have
entered writer waiting will not be accidentally discarded by `try_acquire` because D2 is full of
other control writers. If the relay indeed refuses to forward OPEN due to its own S0/S1 pending
upper limit, use `OpenReject.reason_code=11` to indicate instantaneous local control back pressure.
The source retains the candidate and retries OPEN with backoff. This path must not be
quarantined. The writer's `open_uni`/write still has 5 seconds to cancel the timeout; the timeout
will release the writer slot and close the current Link, which will be restored by Link
replacement/re-auth. Renewal will first make a bounded retry on the active lease under local
admission back pressure or the timeout. Only when it fails in the end will it enter the
cancellation/reconstruction of the Circuit lease. `send_physical()` classifies Probe, Keepalive, and
Forward as D0, D1, and D2 respectively. The control writer also has a concurrency upper limit, and
ACK/Request uses reserved recovery slots. Hello/HelloAck uses the S0 gate of the same connection
before Link is installed, and then the gate is handed over to Link. `stream_admission_rejections`
and `datagram_admission_rejections` appear in Link state and Prometheus metrics. This
implementation only guarantees local admission/writer queue ordering, not the Quinn API, underlying
socket, or send ordering on the wire.

Linux CI runs `tests/remote_quic_mixed_flood_two_node.sh` and
`tests/remote_quicfull_faketcp_two_node.sh`, and the isolated network resources are cleaned by the
test script. Added `tests/remote_relay_control_congestion.sh`: When the three-node fake-TCP
multi-hop path imposes speed limit, delay, packet loss and floods D2 in B↔C, verify that the
preferred-path migration of A/C is still completed within the bounded time, and the test script
cleans up the namespace, TUN, qdisc, routing and daemon.
