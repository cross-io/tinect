# RFC-0010: fake-TCP handshake loss recovery

> Capacity unit supplement (RFC-0037): The QUIC datagram in the outer packet length calculation in
  this article refers to QUIC's application DATAGRAM payload; the upper bound of Quinn's DPLPMTUD
  path-payload differs from it by the current conservative 38 bytes. Unless otherwise specified
  below, `1200` is the initial value of path-payload, corresponding to the initial capacity of
  full QUIC application DATAGRAM `1162`.

- Number: RFC-0010
- Title: fake-TCP handshake packet loss recovery
- Status: Implemented
- Created: 2026-07-25
- Last updated: 2026-08-15

## Background and Problem

QUICP uses a minimal fake-TCP state machine encapsulated in original IP to carry QUIC datagrams.
Original packets may be lost due to path MTU probing, IPv6 forwarding, or kernel queue congestion.
The old implementation has no replay response to repeated SYNs and repeated SYN|ACKs; in addition,
when the handshake ACK is lost, the client may send the first QUIC datagram as an ACK, and the
server will establish the state but discard the datagram, causing QUIC to wait for a timeout, which
is manifested as the node occasionally being unable to establish a link.

## Goals and Non-goals

The goal is to make the handshake convergent with limited packet loss and to ensure that the first
datagram can be delivered with an ACK to establish the connection. Non-goals are to achieve reliable
transmission for the fake-TCP data plane; data reliability is still the responsibility of QUIC, and
it does not change the PMTUD upper limit of QUIC.

## design

1. Each QUICP session saves the latest handshake response: the client saves SYN, the server saves
   SYN|ACK, and after completing the handshake, the ACK for establishing the connection is saved.
2. `SynReceived` replays SYN|ACK when receiving repeated SYN; `Established` replays ACK to
   establish the connection when receiving repeated SYN|ACK. replay does not advance the sequence
   number, nor does it overwrite the session status.
3. `SynReceived` establishes a connection when receiving an ACK that meets the acknowledgment
   number; if the ACK carries a QUIC datagram, the datagram is delivered at the same time and an
   ACK is returned.
4. The handshake response is updated only when the state transitions from non-Established to
   Established; an ACK for a normal packet MUST NOT overwrite this response.
5. The outbound supervisor places a 10-second cap on an underlying dialup. The timeout only ends
   the current attempt, and then re-establishes the session according to the existing backoff
   policy to avoid blocking the entire supervisor with an unresponsive original packet path.
6. fake-TCP only accepts `RST|ACK` explicitly sent by this project in `Established` state, and
   the sequence number and confirmation number match both. The RST in the handshake phase is
   regarded as unauthenticated noise and ignored, and the convergence is retransmitted by
   SYN/SYN|ACK. In this way, even if the native kernel RST guard does not take effect within the
   startup window, QUIC dialing will not be aborted before fake-TCP's SYN|ACK.
7. The reset of an established connection must also carry the standard TCP MD5 Signature option
   (kind 19, len 18); the 16-byte value of the option is the first 16 bytes of
   `HMAC-SHA256(reset_key, address family || client/server ISN || sequence || acknowledgement ||
   RST|ACK)`. RST has no payload, and the TCP window, urgent pointer, and IP ID/IPv6 flow label
   still follow the conventional header semantics. MAC does not bind the original quad because
   stateful NAT overwrites it; therefore the bidirectional ISN of the production path must be
   unpredictable. When the top-level `fake_tcp_reset_key` is omitted, the compatibility default
   value `ihciah/tinect` is used; when set to `false`, reset is disabled and all RSTs are
   ignored; when set to a non-empty string, the shared key is used. The default value is public
   and cannot resist active injection. When deploying to an untrusted path, an independent
   private key must be configured.

## Security and Compatibility

All replay packets still use verified four-tuple and fake-TCP state machine serial numbers, and do
not accept unknown peers or wrong confirmation numbers. RST must match the bidirectional sequence
State of the established session and verify the 128-bit HMAC tag in the TCP MD5 option; RST will
not change the state without the authenticated handshake phase. The security default for the
`false` configuration is to reject all RSTs instead of falling back to sequence number checking.
This change only adds packet loss recovery and does not change QUIC or physical frame format; nodes
using different reset keys will ignore each other's RST and recycle the session through the existing
idle timeout.

## MTU and packet length calculation

When troubleshooting QUICP you must distinguish between "QUIC datagram size" and "on the wire IP
packet size". Fake-TCP does not use UDP port bearers, but adds TCP headers to IP packets:

| Path | IP header | TCP header | QUIC path-payload upper limit (take MTU 1500 as an example) |
| --- | ---: | ---: | ---: |
| IPv4 fake-TCP (data segment) | 20 | 32 (including Timestamp) | 1448 |
| IPv6 fake-TCP (data segment) | 40 | 32 (including Timestamp) | 1428 |

The SYN packet also carries TCP options. Historical implementation is 4 bytes (Window Scale only);
20 bytes as of RFC-0013 (MSS + SACK + Timestamp + WScale), IPv6 SYN on the wire 80 bytes. The TCP
header of the established data segment is 32 bytes, and the length on the wire is `40 + 32 +
quic_datagram_len`. So for IPv6 MTU 1500 (data plane):

```text
max_quic_path_payload = 1500 - 40 - 32 = 1428
max_quic_application_datagram = 1428 - 38 = 1390
initial_quic_path_payload = 1200
initial_quic_application_datagram = 1200 - 38 = 1162
```

The minimum MTU of the IPv6 link is 1280. After deducting the fake-TCP header, there are still 1208
bytes. QUIC's 1200-byte initial path-payload can pass; if the actual path is lower than 1272, the
initial packet will also trigger the kernel `EMSGSIZE` or be dropped by the path. The TUN inner MTU
must also use `UserIpCapacity` published by Link. The 1428 path-payload or 1390 application DATAGRAM
cannot be directly used as the TUN MTU.

The ownership judgment of `EMSGSIZE` is as follows:

1. `RawTcpSocket::try_send()` calls Linux `sendto()`; if the machine knows the export MTU and the
   packet is too large, the error comes from the kernel, usually `EMSGSIZE`, not a QUIC
   rejection.
2. If `sendto()` succeeds but is not received by the peer, the problem lies with neighbor
   resolution, routing, nftables, forwarding paths, or intermediate MTUs; QUIC can only infer
   packet loss through ACK/probe timeouts.
3. QUIC's DPLPMTUD will probe above the initial 1200 bytes, and the current QUICP IPv6
   path-payload upper limit is 1428 (corresponding to application DATAGRAM 1390); it will not
   correct the incorrect IP/TCP header budget for fake-TCP.

## Layered troubleshooting process

When "Inner layer ping fails" appears, follow the following order. Do not increase the number of
ping retries first:

### 1. First confirm whether the physical link authentication is completed.

Check whether `outbound QUIC link authenticated` and the corresponding inbound authenticated log
appear in the logs at both ends. When there is no authentication log, check the fake-TCP/QUIC
handshake first; if there is authentication but the inner layer is blocked, then go to the routing,
forwarding and packet MTU troubleshooting. `ss -nt` is not suitable for judging QUICP sessions
because it is not a kernel TCP connection.

### 2. Check address family, routing, and interface MTU

Execute in the actual network namespace:

```sh
ip -br link
ip -6 addr show dev <underlay-if>
ip -6 route get <peer-ipv6>
ip link show dev <underlay-if>
ip link show dev <tun-if>
```

Confirm that the source address is the configured underlay address, the destination address goes
through the expected interface, the underlay MTU is not less than 1280, and the TUN MTU does not
exceed the upper limit of the inner layer that the current link can carry. When the source address
displayed by `ip -6 route get` is abnormal (such as `::1` or other loopback addresses), correct the
binding address/route first, and then determine QUICP packet loss.

### 3. Check whether the fake-TCP packet reaches both ends

Capture packets on the underlay interface; if you use a test script to create a namespace, you
should capture packets in the corresponding namespace:

```sh
tcpdump -ni <underlay-if> -vv 'ip6 and tcp and (port 4433 or port 4434)'
```

The expected sequence is `SYN -> SYN,ACK -> ACK`, followed by a packet with TCP ACK flag and QUIC
payload. Judgment method:

- SYN only: The server did not receive or accept the destination address, or the intermediate
  path/firewall dropped the packet.
- There are SYN and SYN|ACK, but no ACK: There is a problem with the client's packet reception,
  verification, status conversion, or return path.
- The three-way handshake is complete and there is no QUIC authentication: Check the QUIC initial
  packet size, checksum, DPLPMTUD and authentication configuration.
- There are packets at both ends but TUN is blocked: enter nftables, policy routing,
  forwarding/NAT and inner MTU to troubleshoot.

Do not regard ordinary kernel TCP RST as fake-TCP packets; when configuring `fwmark`, the fake-TCP
original packet carries this `SO_MARK`, and RST guard should only block kernel RSTs with different
marks; when not configured, the default behavior of blocking RST by port is used.

### 4. Check nftables, not iptables

Project constraints are nftables. Check current rules and counters:

```sh
nft -a list ruleset
nft list table ip tinect_input_<tun-name-hex>
nft list table ip6 tinect_input_<tun-name-hex>
```

Verify that fake-TCP input on the underlay is not dropped, that the TUN input chain allows targeted
traffic, and that there are no old systemd services or legacy rules repeatedly overwriting the
current configuration. It is prohibited to use `iptables` to temporarily bypass the problem,
otherwise the real deployment status cannot be reproduced.

### 5. Distinguish between kernel sending failure and path packet loss

If you need to confirm `EMSGSIZE`, you should record the daemon's system call error, interface MTU,
`ip -s link` packet loss count and packet capture length in the test environment; do not rely solely
on QUIC connection timeout. on the wire packet length should satisfy:

```text
IPv6 fake-TCP packet length = 40 + 32 + QUIC application DATAGRAM length
```

For example, when the QUIC datagram is 1097, the on-the-wire IPv6 packet is 1157 bytes, and the
fake-TCP header should not trigger 1280 MTU fragmentation; if 1097 is observed to trigger `frag`,
you should check whether the TUN inner packet length, QUIC datagram length, and outer IP Packet
lengths are conflated, or if there is additional encapsulation (tunnels, encrypted interfaces, NIC
VLANs, etc.). IPv6 does not allow router fragmentation, and packets exceeding the link MTU are
dropped directly and rely on PMTUD.

## Typical fault signatures and repair directions

| Phenomenon | Prioritize suspicion | “Fixes” that should not be taken |
| --- | --- | --- |
| Occasionally there is no authentication log at both ends, and the probability changes after restarting | The first SYN/SYN|ACK is lost, neighbor resolution race condition, and handshake retransmission are missing | Only the number of ping cycles is increased |
| The client has no logs for a long time in a single attempt and fails after about 10 seconds | Outbound attempts wait unbounded or the bottom layer packet collection never wakes up | Infinitely increase the connection timeout |
| `sendto()` returns `EMSGSIZE` | Outer IP/TCP/Path MTU budget error | Ignore error and increase TUN MTU |
| The handshake is completed but the large packet is lost, the small packet is normal | DPLPMTUD upper limit, path black hole or extra encapsulation header | Fixed retrying the same large packet |
| There is data in the packet capture at both ends, but there is no return packet in TUN | nftables, policy routing, forward/NAT or TUN MTU | Temporarily insert iptables to release |

## Repeatable verification

Integration acceptance includes at least:

- After multiple rounds of startup, link authentication and TUN ping can be completed without
  modifying the script retry logic;
- After artificially discarding the first SYN or SYN|ACK, the 250ms-level handshake retransmission
  can be restored; injecting `RST|ACK` in kernel form during the handshake will not abort the
  recovery;
- When `fake_tcp_reset_key: false`, the RST matching the sequence number is still ignored; when
  configuring the key, only the RST carrying the kind-19 option and the correct HMAC can close the
  session, and must be ignored after the tag is tampered with;
- When sending close to path-payload 1200, 1428, 1448 (corresponding to application DATAGRAM 1162,
  1390, 1410), the packet length calculation is consistent with the actual captured packet;
- Large packets below the path MTU can be used to lower the detection limit through QUIC PMTUD
  instead of permanently blocking the supervisor;
- Verified using `cargo fmt --check`, strict Clippy, `cargo test` and real network integration
  testing.

## Testing and Acceptance

- The fake-tcp unit tests cover state conversion of the first datagram carried by ACK, as well as
  handshake RST ignore, safe default value without key, valid TCP-MD5 option RST and tamper tag
  rejection.
- `cargo fmt --check`, Strict Clippy and `cargo test` all passed.
- Run the QUICP two-node network test on the IPv6 underlay to verify replay and link establishment
  after handshake packet loss.

## Implementation Notes

Implement the status machine located at `crates/tinect-fake-tcp` and the session replay logic at
`src/carrier/quicp.rs`.

## Open Questions

- The reset key is currently a node-level shared string; if different peers need to use different
  keys in the future, peer mapping and rotation/hot reloading semantics must be defined, and
  identity or QUIC keys must not be reused.

## Troubleshooting record template

When a QUICP failure occurs later, it is recommended to fill in at least the following fields in the
issue/change record to avoid recording only "ping failed":

```text
commit:
carrier: quicp
address family: ipv4 / ipv6
underlay interface + MTU:
tun interface + MTU:
local/remote endpoint:
authenticated: yes / no
first SYN observed: yes / no
SYN|ACK observed: yes / no
ACK observed: yes / no
largest successful QUIC datagram:
first EMSGSIZE/ICMPv6 Packet Too Big:
nft input/forward counters:
ip -s link counters:
route get result:
daemon logs and pcap path:
cleanup completed: yes / no
```
