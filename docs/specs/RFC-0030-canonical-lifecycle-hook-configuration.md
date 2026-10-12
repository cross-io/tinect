# RFC-0030: Standardized lifecycle hook configuration

- Number: RFC-0030
- Status: Implemented
- Created: 2026-08-10
- Last updated: 2026-08-10

## Background and Problem

`post_up` and `pre_down` accepted two YAML representations, a string or a list of strings. Only the
command list is required at runtime, and the dual representation adds parsing branches and
documentation/test combinations, but no different running semantics.

## Goals and Non-goals

The goal is to normalize lifecycle hooks into non-empty string lists. Non-goals do not change the
order of command execution, environment variables, TUN life cycle, or shell execution boundaries.

## design

`LifecycleCommands` is represented by serde transparent `Vec<String>`; scalar string configuration
is rejected at startup. All valid configurations after deserialization are already in the unique
shape required at runtime.

## Security and Compatibility impact

Does not change the command trust model or network permissions. The previous scalar hook
configuration is no longer compatible; the project does not commit to configuration change
compatibility by default, and deployment should be changed to a single-element list.

## Testing and Acceptance

Covers list acceptance, scalar rejection, and blank/NUL command rejection, and runs full workspace
tests.

## Implementation Notes

2026-08-10: Remove scalar compatible parsing and use unique list representation.
