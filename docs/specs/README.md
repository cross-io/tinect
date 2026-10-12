# Tinect Design Specification (RFC)

This directory holds design decisions that affect protocols, data planes, control planes,
configuration semantics, security boundaries, or operational behavior. An RFC is a reviewable,
traceable record of the design within the repository; implementation, testing, and documentation
should be linked to the corresponding RFC.

## Naming and state

The file name must be `RFC-NNNN-short-kebab-case-Title.md`:

- `NNNN` is a four-digit decimal number that strictly increases from `0001`; once assigned, the
  number cannot be reused.
- Title uses lowercase ASCII and hyphens to describe the topic rather than implementation details.
- The RFC must have Number, Title, state, Created and Last updated at the top.

Allowed state:

- `Draft`: It is under discussion and cannot be used as a basis for implementation.
- `Proposed`: The plan has met the conditions for implementation and is waiting for review or
  acceptance.
- `Accepted`: Accepted, subsequent implementation should follow.
- `Implemented`: Implementation and acceptance are complete.
- `Superseded by RFC-NNNN`: Replaced by subsequent RFC; obsolete documents can be deleted after
  the reference migration is completed, but the Number will never be reused.
- `Rejected`: Clearly reject the application and record the reasons.

## Writing requirements

Except for very minor changes, each RFC contains at least: Background and Problem, goals and
non-goals, terminology, design, protocol/data format, Security and Compatibility impact, migration
or deployment methods, testing and Acceptance Criteria, and unresolved issues. Do not record keys,
tokens, real user data, or other secrets in RFCs.

RFC describes "why" and "what are the constraints"; the relevant code location, commit, or implementation status should be summarized in the
Implementation Notes at the end of the RFC. When implementing changes to the semantics of an Accepted RFC, you should create a new RFC
or explicitly update its state and change records. You cannot just change the design implicitly in
the code.
