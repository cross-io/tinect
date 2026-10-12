# RFC-0009: tun-input-firewall-integration

- Status: Implemented
- Created: 2026-07-25
- Last updated: 2026-08-09

## Background and Problem

Tinect creates an independent nftables INPUT base chain for each TUN and accepts local traffic from
the TUN in it. However, Linux allows multiple base chains to exist on the same hook; `accept` of an
earlier chain will not prevent subsequent host firewall chains from continuing to process packets.
When using the NixOS default firewall, TCP SYNs from TUN are dropped in `nixos-fw-refuse`, causing
ICMP to work but the TCP connection not to be established.

## Goals and Non-goals

The goal is to allow TUN-injected local delivery traffic to obtain the same release semantics as the
Tinect-specific nftables chain on hosts using NixOS firewalls, and only clean up the rules added by
this daemon when the daemon exits.

Non-goals are to modify the host's default firewall policy, allow external interface traffic, or
change Tinect's egress forwarding/NAT policy.

## design

Linux creates a dedicated `tinect_input_<tun-name-hex>` nftables table and `input` base chain
isolated by interface when booting TUN. The rule only matches the target interface, which is in
front of the NixOS firewall; the host-owned `filter INPUT` chain is not read or modified.

The life cycle state records the precise table name used for this startup; during cleanup, only the
dedicated table corresponding to this state is deleted, without touching the pre-existing host
rules.

## Security and Compatibility impact

The rule only matches the TUN interface created by the daemon, allowing packets injected by this
interface to be delivered locally; it does not change the INPUT or FORWARD default policy of the
external interface. Old nodes do not require protocol upgrades, and behavior only affects the native
firewall life cycle.

## Testing and Acceptance

- When Linux has no host INPUT chain, the dedicated nftables transaction can still be mounted and
  cleaned;
- On the NixOS nftables host, the SYN from TUN to the local TCP listener can receive SYN-ACK;
- After the daemon exits normally, the dynamic rules and dedicated nftables table are cleaned up;
- By `cargo fmt --check`, strict clippy and `cargo test`.

## Implementation Notes

Implement `apply_tun_input_firewall`/`cleanup_tun_input_firewall` at `src/platform.rs`.
