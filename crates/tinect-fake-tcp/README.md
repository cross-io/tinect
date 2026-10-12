# tinect-fake-tcp

`tinect-fake-tcp` 将一份 QUIC UDP datagram 作为 TCP payload 编码为完整的 IPv4 或 IPv6
报文，并提供仅覆盖握手、确认和 RST 的最小 TCP 状态机。它有意不实现 TCP 重传、拥塞
控制或流量控制，因此 QUIC 原有的丢包、乱序与拥塞语义仍保持在内层。

为降低部分路径上中间盒对「不像 TCP」流的软丢包，外形会贴近常见主机栈：SYN 通告
MSS、SACK-permitted、Timestamp 与 Window Scale；已建立段携带 Timestamp；应用数据段带
`PSH|ACK`；ACK 序号仅按序推进（乱序 payload 仍交给 QUIC，但 ACK 不回退）。这仍是混淆
而非真 TCP 可靠性。已建立段 TCP 头为 32 字节，QUICP datagram 上限相应下调 12 字节。

这个 crate **不创建 TUN 设备、不打开原始套接字，也不修改路由或防火墙**。调用方负责将
`OutboundPacket` 交给已受控的原始 IP 传输层，并把收到的 IP 报文回送给
`FakeTcpSession::handle_inbound`。

```rust
use std::net::SocketAddr;
use tinect_fake_tcp::{FakeTcpSession, SessionEvent};

let local: SocketAddr = "192.0.2.1:40000".parse()?;
let remote: SocketAddr = "198.51.100.1:443".parse()?;
let mut session = FakeTcpSession::client(local, remote, 7)?;
let syn = session.start()?; // send syn.bytes through the caller's raw-IP transport

// Feed the peer's SYN|ACK packet back to the session, then send event.reply.
let event: SessionEvent = session.handle_inbound(&peer_packet)?;
assert!(event.reply.is_some());

let quic_datagram = session.encapsulate(b"a QUIC UDP payload")?;
```

For an Ethernet MTU of 1500, the maximum inner QUIC UDP datagram is reduced by
12 bytes for IPv4 (TCP replaces UDP: 20 bytes instead of 8) and by 12 bytes for
IPv6 as well. The library sets IPv4 DF and never fragments.

This is packet obfuscation, not encryption or authentication. Use QUIC/TLS for
end-to-end confidentiality and integrity, and only expose packet injection through
an explicitly controlled platform boundary.

RST is authenticated with a 16-byte HMAC carried in the standard TCP MD5
Signature option when the caller supplies a reset key. Callers which do not
supply a key ignore every inbound RST; the daemon exposes this as
`fake_tcp_reset_key` configuration.

## Privileged integration test

On Linux, run `bash tests/remote_fake_tcp_nat.sh` from the repository root. It
builds a test-only raw-IP endpoint, creates isolated client/NAT/server network
namespaces, verifies a fake-TCP handshake, QUIC payload, reset, and conntrack
SNAT traversal, then deletes every namespace. It is intentionally not part of
`cargo test`.
