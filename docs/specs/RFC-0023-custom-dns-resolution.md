# RFC-0023: Configurable DNS upstream resolution

- Number: RFC-0023
- Title: Configured DNS upstream resolution
- Status: Implemented
- Created: 2026-08-05
- Last updated: 2026-08-13

> Current description: RFC-0034 has removed the `health_checks.*.targets` service probe; the DNS
  upstream, peer endpoint multi-address resolution, and underlay address collection portions of
  this RFC remain valid.

## Background and Problem

`peers.*.endpoints` can contain hostname. Previously, they used the operating system resolver
directly, unable to access internal domain names that were only resolvable upstream of the specified
DNS, and the connection code only used the first address in the resolution result.

## Goals and Non-goals

Target:

- Provides a top-level `dns_servers` configuration to sequentially query custom DNS upstreams.
- Fallback to the operating system resolver when all custom upstreams fail.
- Keep all A/AAAA addresses and continue trying subsequent addresses if the connection fails.
- Make peer connections and underlay address collection use consistent parsing semantics.

Non-goals:

- Do not listen to the DNS service locally.
- DoT, DoH or DoQ are not supported.
- `listen` is not allowed to use hostname.
- Do not change the DNS upstream through hot reloading; you need to restart the daemon after
  modification.

## Configuration and semantics

```yaml
dns_servers:
  - "10.0.0.53"
  - "[2001:db8::53]:5353"
```

Each item must be an IP literal, and the port can be omitted. When omitted, use `53`. Hostname is
not allowed as a DNS server address to avoid bootstrap loops caused by resolving the DNS server
itself.

Each parsing first attempts custom servers in the configured order; it ends when one server returns
an available address. The system resolver is used when all custom servers fail or no address is
available. Literal `SocketAddr` does not initiate a DNS query. The resolver caches results following
DNS TTL; custom server uses UDP, allowing TCP fallback when responses are truncated.

## Components and data flows

- `config` is responsible for parsing and verifying `dns_servers`.
- `dns` encapsulates a shared, cloneable asynchronous resolver and provides resolution from
  `HOST:PORT` to multiple `SocketAddr`.
- `runtime::Runtime` holds the shared resolver.
- The peer connection supervisor attempts the resolved addresses in order.
- The underlay route collects and retains all resolved peer endpoint IPs.

DNS query is an outbound control operation of the daemon and does not change the wire protocol or
bypass the egress policy; the DNS server address itself will not be written to the overlay route or
exposed to the management interface.

## Security, compatibility and failure handling

Empty `dns_servers` maintains the original system resolver behavior. Customizing the system fallback
when DNS query fails maintains the availability of the existing deployment, but may cause the query
to leave the specified DNS management boundary; if operators need strict DNS isolation, they should
block the system resolver through the host network policy instead of relying on this configuration
field.

DNS resolution failure only causes the current peer connection to fail and does not change the ACL,
routing authorization, and encryption boundaries.

## Testing and Acceptance

- Verify IPv4, IPv6, default port, custom port and illegal server address.
- Use local DNS test server to verify server order, A/AAAA multi-address, TCP fallback and system
  fallback.
- Verifying the peer connection will try subsequent addresses.
- Through `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo
  test ` and ` nix flake check`.

## Implementation Notes

- `src/config.rs` adds `DnsServer` and `Config::dns_servers`.
- `src/dns.rs` provides shared resolver.
- `src/main.rs` uses this resolver; the service probe caller no longer exists after RFC-0034.
