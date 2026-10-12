//! Runtime-owned assembly facade for the independent Circuit managers.

use super::LinkRegistry;
use crate::{
    dataplane::{CircuitOpenManager, SessionManager},
    link::{LinkDirectory, LinkRef},
    return_path::ReturnFlowTable,
};

/// Groups Circuit dependencies for composition without merging their locks or
/// hot paths into one manager or state machine.
#[derive(Clone, Default)]
pub struct CircuitRuntime {
    pub sessions: SessionManager,
    pub opens: CircuitOpenManager,
    pub return_flows: ReturnFlowTable,
    pub circuit_dns: crate::dataplane::CircuitDnsClient,
}

impl LinkDirectory for LinkRegistry {
    fn by_peer(&self, peer_identity: &str) -> Option<LinkRef> {
        self.lock()
            .expect("link registry lock")
            .values()
            .find(|link| link.peer_identity == peer_identity)
            .cloned()
            .map(|link| link as LinkRef)
    }

    fn by_instance(&self, instance: u64) -> Option<LinkRef> {
        self.lock()
            .expect("link registry lock")
            .values()
            .find(|link| link.instance() == instance)
            .cloned()
            .map(|link| link as LinkRef)
    }
}
