# RFC-0035: SiteSet and Unified Route Selector

- Status: Implemented
- Created: 2026-08-13
- Last updated: 2026-08-13

## Background and Goals

The original configuration used `domain_set` and `ip_cidr_set` files respectively, and used `prefix`
to represent a single CIDR. The two sets of sets result in duplication of configuration models and
make it difficult for large domain name lists and CIDR lists to share the same immutable index.

This RFC unifies route selectors into `ip_cidr`, `domain`, and `site_set`, and allows a site set to
contain both domain name rules and IP-CIDR rules. The goal is to maintain existing route precedence,
FakeIP, longest prefix, and control plane behavior while sharing an immutable memory structure of
equivalent routes during the configuration load phase.

## Configuration format

The selector for each peer route, direct route, and path override must contain only one of the
following fields:

```yaml
- ip_cidr: 192.0.2.0/24
- domain: example.com
- site_set: ./rules/sites.txt
```

Old `prefix`, `domain_set`, `ip_cidr_set` and bare CIDR shorthands are rejected. Non-route selector
fields such as `nft_healthy_set.prefix` are not affected.

## SiteSet file syntax

The file is parsed line by line, `#`, `//` or `;` comments are removed, blank lines are ignored, and
only the first blank-delimited field is read; subsequent label fields do not participate in the
rules.

- `example.com` matches itself and all subdomain names.
- `full:example.com` only matches itself.
- Each domain name label contains at most one `*`; `*` matches zero or more non-`.` characters.
- `ip-cidr:192.0.2.0/24` joins the CIDR set and participates in longest prefix matching based on
  the normalized CIDR.
- `regexp:`, old `.example.com`, duplicate wildcards, illegal domain names, and illegal CIDRs can
  cause configuration loading to fail.

Domain name rules are uniformly converted to ASCII lowercase and the root domain name dot at the end
is removed. Domain names and CIDR rules are sorted and duplicated before participating in canonical
content hashing.

## Indexing and sharing

Each canonical SiteSet is referenced by a `SetId` and shared with `Arc` in `RouteSetRegistry`.
SiteSet contains:

- The exact hashmap of the domain name itself;
- Reverse label trie starting from TLD;
- A normal label hashmap for each trie node;
- Multiple wildcard edges, each edge stores prefix, suffix and next node;
- Normalized CIDR list.

The query of the domain name without wildcard will first go through the accurate hashmap; the query
of the subdomain name and wildcard will go through the reverse trie. Two branches are retained when
normal edges and wildcard edges exist at the same time. wildcard does not span dot-delimited labels.

Files are deduplicated by canonical path, and equivalent canonical content is deduplicated by
SHA-256. `domain` and `ip_cidr` are also compiled into an inline SiteSet containing only one rule,
and therefore share the same `SetId` with the content-equivalent `site_set`.

After loading all peers, paths and direct routes, the configuration will also share the canonical
selector intern `Arc<SharedRouteSelector>`, the normal route will share `Arc<SharedRouteSpec>`
according to `(SetId, priority)`, and the override will share the override spec according to
selector, priority and priority delta. Peer identity, candidate priority, Circuit, Link and health
State are still saved separately.

## routing behavior

The `ip-cidr:` rule of SiteSet enters the IP longest prefix index, and the domain name rule enters
the FakeIP domain name candidate index; both share the route priority that declares the site set.
`domain` only generates domain name candidates, and `ip_cidr` only generates IP candidates.

The path override determines whether the selectors are the same according to the canonical final
matching content, so `domain`, `ip_cidr` and `site_set` with equivalent content can overwrite each
other. A wildcard override that does not specify a selector continues to override all declared
routes for that destination.

When FakeIP is not configured, the `domain` route or `site_set` route containing domain name rules
is rejected; site sets containing only CIDR do not require FakeIP.

## Security, compatibility and migration

This is an incompatible change in configuration semantics and does not change the wire protocol or
end-to-end encryption format. Deployers must put:

- `prefix: CIDR` is changed to `ip_cidr: CIDR`;
- `domain_set: file` is changed to `site_set: file`;
- Change `ip_cidr_set: file` to `site_set: file`, and write the CIDR in the file as
  `ip-cidr:CIDR`;
- The old `.domain` rule is changed to the bare domain name, and the old precise domain name is
  changed to `full:domain`.

## Test acceptance

Tests must cover SiteSet hybrid resolution, bare domain names, `full:`, wildcard, CIDR, illegal
rules, FakeIP missing rejects, canonical SetId sharing, route interning, longest prefix, domain
candidate, direct/fallback, and existing FakeIP end-to-end paths.
