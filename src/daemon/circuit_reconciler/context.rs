//! Circuit reconciliation context: one assembled view over runtime state.
use super::*;
#[derive(Clone)]
pub(crate) struct CircuitReconcileContext {
    pub(crate) config: Arc<Config>,
    pub(crate) links: LinkRegistry,
    pub(crate) topology: SharedTopology,
    pub(crate) state: SharedDaemonState,
    pub(crate) circuit_opens: dataplane::CircuitOpenManager,
    pub(crate) sessions: dataplane::SessionManager,
    pub(crate) return_flows: tinect::return_path::ReturnFlowTable,
    pub(crate) circuit_dns: dataplane::CircuitDnsClient,
    pub(crate) supervisor: DaemonSupervisor,
    pub(crate) source_key: Arc<ed25519_dalek::SigningKey>,
}

impl CircuitReconcileContext {
    pub(crate) fn new(
        runtime: &Runtime,
        key: Arc<ed25519_dalek::SigningKey>,
        supervisor: DaemonSupervisor,
    ) -> Self {
        Self {
            config: runtime.config.clone(),
            links: runtime.links.clone(),
            topology: runtime.topology.clone(),
            state: runtime.state.clone(),
            circuit_opens: runtime.circuits.opens.clone(),
            sessions: runtime.circuits.sessions.clone(),
            return_flows: runtime.circuits.return_flows.clone(),
            circuit_dns: runtime.circuits.circuit_dns.clone(),
            supervisor,
            source_key: key,
        }
    }
}
