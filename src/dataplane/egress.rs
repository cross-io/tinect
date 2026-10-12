//! Egress and source-address authorization boundaries shared by all decrypting
//! dataplanes.

use super::*;
use crate::identity;

/// Conditional source-address authorization. Valid IP addresses without any
/// configured binding remain unrestricted; once one or more bindings match,
/// the authenticated source identity must be one of their owners. Malformed
/// or unsupported IP packets are always rejected.
#[derive(Clone)]
pub struct SourceAddressPolicy {
    bindings: Arc<HashMap<IpNet, HashSet<String>>>,
    metrics: Arc<Observability>,
}

impl Default for SourceAddressPolicy {
    fn default() -> Self {
        Self {
            bindings: Arc::new(HashMap::new()),
            metrics: Arc::new(Observability::new(0)),
        }
    }
}

impl SourceAddressPolicy {
    pub fn from_config(config: &crate::config::Config, metrics: Arc<Observability>) -> Self {
        let mut bindings = HashMap::<IpNet, HashSet<String>>::new();
        for (prefix, public_key) in config.source_bindings() {
            let owners = bindings.entry(prefix).or_default();
            owners.insert(public_key.clone());
            if let Ok(key) = identity::decode_public(&public_key) {
                owners.insert(identity::node_id(&key));
            }
        }
        Self {
            bindings: Arc::new(bindings),
            metrics,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_bindings(
        bindings: impl IntoIterator<Item = (IpNet, String)>,
        metrics: Arc<Observability>,
    ) -> Self {
        let mut grouped = HashMap::<IpNet, HashSet<String>>::new();
        for (prefix, owner) in bindings {
            grouped.entry(prefix).or_default().insert(owner);
        }
        Self {
            bindings: Arc::new(grouped),
            metrics,
        }
    }

    /// Authorizes an already authenticated source identity against the inner
    /// IP source. Matching bindings are unioned across overlapping CIDRs.
    pub fn authorize(&self, source_identity: &str, packet: &[u8]) -> bool {
        let Some(source) = inspect_ip_source(packet) else {
            self.metrics
                .reject("source_binding:unsupported_or_malformed");
            return false;
        };
        let mut has_binding = false;
        for (prefix, owners) in self.bindings.iter() {
            if prefix.contains(&source) {
                has_binding = true;
                if owners.contains(source_identity) {
                    return true;
                }
            }
        }
        if has_binding {
            self.metrics.reject("source_binding:denied");
            false
        } else {
            true
        }
    }
}

#[derive(Clone)]
pub struct EgressPolicy {
    pub names: Arc<HashMap<String, String>>,
    pub allowed_routes: Arc<Vec<crate::config::AllowedRoute>>,
    pub allowed_local_ports: Arc<Vec<crate::config::AllowedLocalPort>>,
    /// Addresses assigned to this node's TUN. Local delivery is governed by
    /// `allowed_local_ports`, not by the exported-route allowlist.
    pub local_addresses: Arc<Vec<IpNet>>,
    pub metrics: Arc<Observability>,
}

impl EgressPolicy {
    /// Egress ACL authorization. The source-address binding check is a
    /// separate unconditional gate in the receive paths.
    pub(super) async fn authorize(&self, source_key: &str, packet: &[u8]) -> bool {
        let known_source = self.names.contains_key(source_key);
        let source = self
            .names
            .get(source_key)
            .map(String::as_str)
            .unwrap_or(source_key);
        let Some(meta) = inspect_packet(packet) else {
            self.metrics.reject("egress:unsupported_or_malformed");
            return false;
        };
        let local_delivery = self
            .local_addresses
            .iter()
            .any(|prefix| prefix.contains(&meta.destination));
        if !local_delivery && !self.permits_export(source, meta.destination, known_source) {
            self.metrics.reject("egress:allowed_route_denied");
            return false;
        }
        let allowed = if self.allowed_local_ports.is_empty() {
            known_source
        } else {
            self.allowed_local_ports.iter().any(|rule| {
                rule.permits(source, meta.protocol, meta.destination_port, known_source)
            }) && !self
                .allowed_local_ports
                .iter()
                .any(|rule| rule.denies(source, meta.protocol, meta.destination_port, known_source))
        };
        if !allowed {
            self.metrics.reject("egress:allowed_local_port_denied");
        }
        allowed
    }

    /// Authorize a DNS upstream selected by the source node. DNS transport is
    /// an internal Circuit service, so only the exported destination policy
    /// applies; `allowed_local_ports` continues to describe plaintext IP traffic.
    pub(super) fn authorize_dns_upstream(&self, source_key: &str, destination: IpAddr) -> bool {
        let known_source = self.names.contains_key(source_key);
        let source = self
            .names
            .get(source_key)
            .map(String::as_str)
            .unwrap_or(source_key);
        if self.permits_export(source, destination, known_source) {
            true
        } else {
            self.metrics.reject("egress:dns_allowed_route_denied");
            false
        }
    }

    fn permits_export(&self, source: &str, destination: IpAddr, known: bool) -> bool {
        self.allowed_routes
            .iter()
            .any(|route| route.permits(source, destination, known))
    }
}
