use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Debug, Clone)]
pub struct TransitPolicy {
    default_allow: bool,
    peer_overrides: HashMap<String, Option<bool>>,
}

impl Default for TransitPolicy {
    fn default() -> Self {
        Self::new(true, HashMap::new())
    }
}

impl TransitPolicy {
    pub fn new(default_allow: bool, peer_overrides: HashMap<String, Option<bool>>) -> Self {
        Self {
            default_allow,
            peer_overrides,
        }
    }

    pub fn permits(&self, source: &str) -> bool {
        self.peer_overrides
            .get(source)
            .copied()
            .flatten()
            .unwrap_or(self.default_allow)
    }
}
