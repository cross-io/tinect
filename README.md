# Tinect

[![codecov](https://codecov.io/gh/cross-io/tinect/branch/master/graph/badge.svg)](https://codecov.io/gh/cross-io/tinect) [![CI](https://github.com/cross-io/tinect/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cross-io/tinect/actions/workflows/ci.yml)

[简体中文](README.zh-CN.md)

Tinect is a policy-driven Layer 3 overlay network. It separates **routing** (which egress handles a destination), **paths** (which peers traffic crosses), and **circuits** (the forwarding state installed along a path).

Tinect supports authenticated peer links, end-to-end encrypted circuits, multi-hop relaying, dynamic path selection, failover, egress ACLs, and optional FakeIP-based domain routing. Relays forward encrypted circuit payloads without decrypting them. Linux and macOS are supported.

## Core features

Inspired by tinc, Tinect adds explicit control over which peers traffic traverses, adaptive FEC for underlay packet loss, and a built-in Fake TCP carrier for UDP-restricted networks.

1. **Policy-driven Layer 3 forwarding** — Configure destination routes, egress selection, peer paths, and circuit forwarding independently. Tinect selects routes by prefix, priority, and link health, with optional fallback to the local egress.
2. **Explicit multi-hop path control and recovery** — Configure preferred and candidate paths for each egress to control which peers traffic traverses. Tinect tracks link health and can rebuild or migrate circuits when a path fails.
3. **Authenticated identities and end-to-end encryption** — Peers authenticate with Ed25519 identities. Circuit payloads use ChaCha20-Poly1305 keys derived from ephemeral X25519 keys; relays forward ciphertext without decrypting it.
4. **Fine-grained traffic policy and egress control** — Apply per-peer route and port ACLs. Optional FakeIP enables domain-based routing with mixed domain/CIDR site sets; local egress can also participate in route selection or serve as a fallback.
5. **Adaptation for constrained underlay links** — Link-level datagram FEC operates independently on each physical link and adjusts its repair rate to observed packet loss, balancing recovery capability with bandwidth overhead. When UDP is throttled or deprioritized, the built-in Fake TCP carrier provides a TCP-shaped alternative. Fake TCP is currently Linux-only and requires raw-socket privileges.

## Install and run

Build from source with Rust:

```sh
cargo build --release --locked
```

On Linux, building from source requires the `libmnl` and `libnftnl` development libraries and `pkg-config`. The Nix package provides its build dependencies.

Or use the Nix flake:

```sh
nix build github:cross-io/tinect
nix run github:cross-io/tinect -- --help
```

Create a node identity, inspect the example configuration, and start a node:

```sh
./target/release/tinect keygen --output node.key
./target/release/tinect pubkey --key node.key
cp examples/client.yaml node.yaml
./target/release/tinect check node.yaml
sudo ./target/release/tinect up node.yaml
```

Edit `node.yaml` to add your peers and routes before connecting other nodes. The example uses `identity_key_path: ./node.key`, so keep the generated key beside the copied configuration. `up` applies the configured network changes and requires the permissions needed to create a TUN interface and manage routes and firewall resources. Review the planned changes first with `./target/release/tinect up node.yaml --dry-run`. For a relay that does not create a local TUN interface, set `tun.enabled: false`.

## Documentation

- [Configuration guide](docs/config.md)
- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Network routing and firewall behavior](docs/netfilter-routing.md)
- [Example configuration](examples/client.yaml)
- [Detailed usage guide](docs/usage.md)
- [Design RFCs](docs/specs/README.md)

## Security

Peer identities use Ed25519 public keys. Circuit payloads are end-to-end encrypted with keys derived from authenticated ephemeral X25519 keys. Relays do not decrypt those payloads. Configure explicit peer allowlists and egress rules for your deployment; PCAP capture is disabled by default because it contains decrypted inner packets.

Tinect is experimental software. Review the security and networking documentation before using it on a production network.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
