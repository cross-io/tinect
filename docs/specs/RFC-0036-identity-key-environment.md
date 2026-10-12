# RFC-0036: Providing node identity private key via environment variable

- Status: Implemented
- Created: 2026-08-13
- Last updated: 2026-08-13

## Background and Problem

The node identity private key must currently be provided via `identity_key` or `identity_key_path`
in the configuration. Writing private keys directly to YAML increases the risk of secrets being
leaked through configuration backups, logs, and deployment systems; some deployment environments
also only allow secret injection through the process environment.

## Goals and Non-goals

The goal is to allow the daemon to read the Base64-no-pad Ed25519 private key from an environment
variable named `IDENTITY_KEY`, and define a clear priority with an existing configured source.
Configuration loading must fail when all identity sources are missing.

This RFC does not change the behavior of private key encoding, node public keys, identity
derivation, wire protocol, or `identity_key_path` in configuration files, nor does it add implicit
environment variable sources for other CLI subcommands.

## design

The identity source priority is fixed to:

1. `IDENTITY_KEY` environment variable;
2. `identity_key` in configuration;
3. `identity_key_path` in configuration.

Environment variables take precedence as long as they exist; empty or illegal values   do not fall
back silently to the configuration, but are treated as invalid Ed25519 private keys. The startup
also fails when the environment variable cannot be interpreted in UTF-8. `identity_key` and
`identity_key_path` must still not appear at the same time in the configuration to maintain the
clarity of the configuration itself; environment variables can coexist with either source.

Configuration verification checks for the existence of `IDENTITY_KEY` when there is no configuration
source. The final chosen identity is still only loaded once during actual startup, and the same
signing key is shared with the daemon worker.

## Security and Compatibility impact

Environment variables avoid writing private keys to YAML, but environment variables may be exposed
by process managers, diagnostic tools, or misconfigured logging; deployers should still use a
controlled secret injection mechanism. Environment variable priority means that setting the wrong
`IDENTITY_KEY` will overwrite an originally valid configuration private key, so the deployment
system must ensure that the content of the environment variable is correct.

Existing deployments configured with only `identity_key` or `identity_key_path` remain compatible.
New deployments that configure only `IDENTITY_KEY` do not need to write the identity private key in
YAML.

## Testing and Acceptance

- Identities can still be loaded when only `identity_key` is configured or only
  `identity_key_path` is configured.
- The identity can only be loaded when `IDENTITY_KEY` is provided.
- When the environment variable coexists with `identity_key`, the public key is derived from the
  environment variable.
- Configuration loading failed without environment variables, `identity_key` and
  `identity_key_path`.
- Instead of falling back to other sources, an error is reported when an environment variable is
  empty, illegal, or non-UTF-8.
- Simultaneous configuration of `identity_key` and `identity_key_path` is still rejected.

## Implementation Notes

The identity source resolution is located at `Config::load_identity`, and the configuration
verification and user documents are updated simultaneously.
