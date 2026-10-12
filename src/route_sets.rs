//! Immutable, process-local site-set storage.
//!
//! Route entries retain only a small [`SetId`]. Canonical files, inline route
//! selectors, and equivalent parsed content share one immutable [`SiteSet`].
//! A site set may contain both domain rules and IP-CIDR prefixes.

use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

pub type SetId = u32;

#[derive(Debug)]
pub enum RouteSet {
    Site(SiteSet),
}

/// One canonical, immutable route selector.
#[derive(Debug)]
pub struct SiteSet {
    domains: DomainMatcher,
    prefixes: Vec<IpNet>,
    entry_count: usize,
    has_domains: bool,
}

impl SiteSet {
    pub fn matches_domain(&self, domain: &str) -> bool {
        self.domains.matches(domain)
    }

    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    pub fn has_domains(&self) -> bool {
        self.has_domains
    }

    pub fn len(&self) -> usize {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MatchFlags {
    bare: bool,
    full: bool,
}

#[derive(Debug, Default)]
struct DomainMatcher {
    /// Non-wildcard rules are checked directly before walking the trie. A
    /// bare rule is included here as well so a query for the rule itself is
    /// an O(1) lookup; the trie handles its subdomains.
    exact: HashMap<String, MatchFlags>,
    root: TrieNode,
    rule_count: usize,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    wildcards: Vec<WildcardEdge>,
    bare: bool,
    full: bool,
}

#[derive(Debug)]
struct WildcardEdge {
    prefix: String,
    suffix: String,
    node: TrieNode,
}

impl DomainMatcher {
    fn insert(&mut self, domain: &str, full: bool) -> Result<(), ()> {
        let labels = domain.split('.').rev().collect::<Vec<_>>();
        let mut node = &mut self.root;
        for label in labels {
            if let Some(index) = label.find('*') {
                let prefix = label[..index].to_owned();
                let suffix = label[index + 1..].to_owned();
                let edge = node
                    .wildcards
                    .iter()
                    .position(|edge| edge.prefix == prefix && edge.suffix == suffix);
                node = if let Some(index) = edge {
                    &mut node.wildcards[index].node
                } else {
                    node.wildcards.push(WildcardEdge {
                        prefix,
                        suffix,
                        node: TrieNode::default(),
                    });
                    &mut node
                        .wildcards
                        .last_mut()
                        .expect("wildcard edge was just inserted")
                        .node
                };
            } else {
                node = node.children.entry(label.to_owned()).or_default();
            }
        }
        if full {
            node.full = true;
        } else {
            node.bare = true;
        }
        self.rule_count += 1;
        Ok(())
    }

    fn insert_exact_flag(&mut self, domain: &str, full: bool) {
        let flags = self.exact.entry(domain.to_owned()).or_default();
        if full {
            flags.full = true;
        } else {
            flags.bare = true;
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return false;
        }
        if let Some(flags) = self.exact.get(&domain)
            && (flags.bare || flags.full)
        {
            return true;
        }

        let labels = domain.split('.').collect::<Vec<_>>();
        let mut pending = vec![(&self.root, labels.len())];
        while let Some((node, remaining)) = pending.pop() {
            if node.bare || (remaining == 0 && node.full) {
                return true;
            }
            if remaining == 0 {
                continue;
            }
            let label = labels[remaining - 1];
            if let Some(child) = node.children.get(label) {
                pending.push((child, remaining - 1));
            }
            for edge in &node.wildcards {
                if wildcard_matches(label, &edge.prefix, &edge.suffix) {
                    pending.push((&edge.node, remaining - 1));
                }
            }
        }
        false
    }
}

fn wildcard_matches(label: &str, prefix: &str, suffix: &str) -> bool {
    label.len() >= prefix.len() + suffix.len()
        && label.starts_with(prefix)
        && label.ends_with(suffix)
}

#[derive(Debug, Default, Clone)]
pub struct RouteSetRegistry {
    sets: Arc<Vec<Arc<RouteSet>>>,
}

impl RouteSetRegistry {
    pub fn get(&self, id: SetId) -> Option<&Arc<RouteSet>> {
        self.sets.get(id as usize)
    }

    pub fn site(&self, id: SetId) -> Option<&SiteSet> {
        match self.get(id)?.as_ref() {
            RouteSet::Site(set) => Some(set),
        }
    }

    pub fn entry_count(&self, id: SetId) -> usize {
        self.site(id).map_or(0, SiteSet::len)
    }
}

pub struct RouteSetLoader {
    base: PathBuf,
    sets: Vec<Arc<RouteSet>>,
    by_path: HashMap<PathBuf, SetId>,
    by_hash: HashMap<[u8; 32], SetId>,
}

impl RouteSetLoader {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            sets: Vec::new(),
            by_path: HashMap::new(),
            by_hash: HashMap::new(),
        }
    }

    pub fn load(&mut self, configured: &str) -> Result<SetId, RouteSetError> {
        let input = Path::new(configured);
        let joined = if input.is_absolute() {
            input.to_owned()
        } else {
            self.base.join(input)
        };
        let canonical = fs::canonicalize(&joined).map_err(|source| RouteSetError::Io {
            path: joined.clone(),
            source,
        })?;
        if let Some(id) = self.by_path.get(&canonical) {
            return Ok(*id);
        }
        let text = fs::read_to_string(&canonical).map_err(|source| RouteSetError::Io {
            path: canonical.clone(),
            source,
        })?;
        let parsed = parse_site_set(&text, &canonical)?;
        let id = self.insert(parsed)?;
        self.by_path.insert(canonical, id);
        Ok(id)
    }

    pub fn load_inline(&mut self, rule: &str) -> Result<SetId, RouteSetError> {
        let parsed = parse_site_set(rule, Path::new("<inline route selector>"))?;
        self.insert(parsed)
    }

    fn insert(&mut self, parsed: ParsedSiteSet) -> Result<SetId, RouteSetError> {
        if let Some(id) = self.by_hash.get(&parsed.hash) {
            return Ok(*id);
        }
        let id = u32::try_from(self.sets.len()).map_err(|_| RouteSetError::TooMany)?;
        self.sets.push(Arc::new(RouteSet::Site(parsed.site)));
        self.by_hash.insert(parsed.hash, id);
        Ok(id)
    }

    pub fn finish(self) -> RouteSetRegistry {
        RouteSetRegistry {
            sets: Arc::new(self.sets),
        }
    }
}

struct ParsedSiteSet {
    site: SiteSet,
    hash: [u8; 32],
}

fn parse_site_set(text: &str, path: &Path) -> Result<ParsedSiteSet, RouteSetError> {
    let mut domains = HashMap::<String, MatchFlags>::new();
    let mut prefixes = Vec::new();
    let mut canonical = Vec::<String>::new();

    for (index, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let token = line.split_whitespace().next().expect("non-empty line");
        if let Some(value) = token.strip_prefix("ip-cidr:") {
            let prefix = value
                .parse::<IpNet>()
                .map_err(|error| RouteSetError::Invalid {
                    path: path.to_owned(),
                    line: index + 1,
                    detail: format!("invalid ip-cidr: {error}"),
                })?
                .trunc();
            prefixes.push(prefix);
            continue;
        }
        let (full, domain) = parse_domain_rule(token, path, index + 1)?;
        let flags = domains.entry(domain.clone()).or_default();
        if full {
            flags.full = true;
            canonical.push(format!("full:{domain}"));
        } else {
            flags.bare = true;
            canonical.push(domain);
        }
    }

    prefixes.sort_unstable();
    prefixes.dedup();
    let mut matcher = DomainMatcher::default();
    let mut domain_rules = domains.into_iter().collect::<Vec<_>>();
    domain_rules.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    canonical.clear();
    for (domain, flags) in &domain_rules {
        if flags.bare {
            if !domain.contains('*') {
                matcher.insert_exact_flag(domain, false);
            }
            matcher.insert(domain, false).expect("validated domain");
            canonical.push(domain.clone());
        }
        if flags.full {
            if !domain.contains('*') {
                matcher.insert_exact_flag(domain, true);
            }
            matcher.insert(domain, true).expect("validated domain");
            canonical.push(format!("full:{domain}"));
        }
    }
    canonical.extend(prefixes.iter().map(|prefix| format!("ip-cidr:{prefix}")));
    canonical.sort_unstable();
    canonical.dedup();

    let mut digest = Sha256::new();
    for entry in &canonical {
        digest.update(entry.as_bytes());
        digest.update(b"\n");
    }
    let hash = digest.finalize().into();
    let has_domains = matcher.rule_count != 0;
    Ok(ParsedSiteSet {
        site: SiteSet {
            domains: matcher,
            entry_count: canonical.len(),
            has_domains,
            prefixes,
        },
        hash,
    })
}

fn strip_comment(value: &str) -> &str {
    ["#", "//", ";"]
        .iter()
        .filter_map(|marker| value.find(marker))
        .min()
        .map_or(value, |index| &value[..index])
}

fn parse_domain_rule(
    token: &str,
    path: &Path,
    line: usize,
) -> Result<(bool, String), RouteSetError> {
    if token.starts_with("regexp:") {
        return Err(RouteSetError::Invalid {
            path: path.to_owned(),
            line,
            detail: "regexp: rules are not supported".into(),
        });
    }
    let (full, value) = token
        .strip_prefix("full:")
        .map_or((false, token), |value| (true, value));
    let value = normalize_domain(value);
    if value.starts_with('.') || !valid_domain(&value) {
        return Err(RouteSetError::Invalid {
            path: path.to_owned(),
            line,
            detail: "invalid domain".into(),
        });
    }
    Ok((full, value))
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.matches('*').count() <= 1
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'*'
                })
        })
}

#[derive(Debug, Error)]
pub enum RouteSetError {
    #[error("failed to read site set {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid site set {path} at logical line {line}: {detail}")]
    Invalid {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    #[error("too many distinct site sets")]
    TooMany,
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_rules_support_bare_full_and_subdomains() {
        let parsed =
            parse_site_set("example.com\nfull:exact.example\n", Path::new("test")).unwrap();
        assert!(parsed.site.matches_domain("example.com"));
        assert!(parsed.site.matches_domain("www.example.com"));
        assert!(parsed.site.matches_domain("exact.example"));
        assert!(!parsed.site.matches_domain("www.exact.example"));
        assert!(!parsed.site.matches_domain("notexample.com"));
    }

    #[test]
    fn wildcard_matches_only_inside_one_label() {
        let parsed = parse_site_set(
            "foo*bar.example.com\n*.wild.example.com\n",
            Path::new("test"),
        )
        .unwrap();
        assert!(parsed.site.matches_domain("foobar.example.com"));
        assert!(parsed.site.matches_domain("foo-123-bar.example.com"));
        assert!(parsed.site.matches_domain("a.wild.example.com"));
        assert!(!parsed.site.matches_domain("foo.bar.example.com"));
    }

    #[test]
    fn site_set_parses_ip_cidrs_tags_comments_and_empty_lines() {
        let parsed = parse_site_set(
            "# comment\n\nip-cidr:192.0.2.9/24 @test\nexample.com @ads\n",
            Path::new("test"),
        )
        .unwrap();
        assert_eq!(parsed.site.prefixes(), &["192.0.2.0/24".parse().unwrap()]);
        assert!(parsed.site.matches_domain("www.example.com"));
        assert_eq!(parsed.site.len(), 2);
        assert!(parsed.site.has_domains());
    }

    #[test]
    fn unsupported_and_legacy_rules_are_rejected() {
        assert!(parse_site_set("regexp:^example$\n", Path::new("test")).is_err());
        assert!(parse_site_set(".example.com\n", Path::new("test")).is_err());
        assert!(parse_site_set("a*b*c.example\n", Path::new("test")).is_err());
    }

    #[test]
    fn content_hash_deduplicates_equivalent_site_sets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), "Example.com\nip-cidr:192.0.2.9/24\n").unwrap();
        fs::write(
            dir.path().join("b"),
            "ip-cidr:192.0.2.0/24 # same\nexample.com @tag\n",
        )
        .unwrap();
        let mut loader = RouteSetLoader::new(dir.path());
        let a = loader.load("a").unwrap();
        let b = loader.load("b").unwrap();
        assert_eq!(a, b);
        assert_eq!(loader.finish().sets.len(), 1);
    }

    #[test]
    fn inline_domain_and_cidr_share_with_file_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("site"), "example.com\n").unwrap();
        let mut loader = RouteSetLoader::new(dir.path());
        assert_eq!(
            loader.load("site").unwrap(),
            loader.load_inline("example.com").unwrap()
        );
    }

    #[test]
    fn empty_sets_and_loader_errors_are_reported_without_panicking() {
        let empty = parse_site_set("# only comments\n; and whitespace\n", Path::new("test"))
            .unwrap()
            .site;
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(!empty.has_domains());
        assert!(!empty.matches_domain("example.com"));

        let mut loader = RouteSetLoader::new("/definitely/missing");
        assert!(loader.load("missing.txt").is_err());
        assert!(loader.load("missing.txt").is_err());
        let registry = loader.finish();
        assert!(registry.get(0).is_none());
        assert!(registry.site(0).is_none());
        assert_eq!(registry.entry_count(0), 0);
        assert!(parse_site_set("ip-cidr:not-a-prefix\n", Path::new("test")).is_err());
        assert!(parse_site_set("host.name\n", Path::new("test")).is_ok());
    }
}
