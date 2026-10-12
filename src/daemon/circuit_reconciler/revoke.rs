//! Authenticated teardown of the active circuit (local revoke, best-effort remote CLOSE).
use super::*;
/// Remove local send/auth/session/flow state before attempting the best-effort
/// remote CLOSE. A blocked or closed control stream must never delay local
/// hard revocation or leave the old lease eligible for dataplane sends.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn hard_revoke_active_circuit(
    circuit_opens: &dataplane::CircuitOpenManager,
    sessions: &dataplane::SessionManager,
    return_flows: &tinect::return_path::ReturnFlowTable,
    circuit_dns: &dataplane::CircuitDnsClient,
    destination: &str,
    active: &dataplane::ActiveCircuit,
    links: &LinkRegistry,
    source_key: &ed25519_dalek::SigningKey,
    supervisor: &DaemonSupervisor,
    reason: &'static str,
) {
    let link = registered_link_by_instance(links, active.link_instance);
    let close = link
        .as_ref()
        .map(|_| ControlMessage::circuit_close(source_key, active.circuit_id, 1, 1));
    circuit_opens
        .deactivate(destination, active.circuit_id)
        .await;
    sessions
        .remove_circuit(active.link_instance, active.circuit_id)
        .await;
    return_flows.remove_circuit(active.link_instance, active.circuit_id);
    circuit_dns.remove_circuit(active.link_instance, active.circuit_id);
    circuit_opens.clear_migration(destination).await;
    tracing::info!(destination, reason, "active circuit hard-revoked");
    if let (Some(link), Some(close)) = (link, close) {
        let destination = destination.to_owned();
        supervisor.spawn_background(async move {
            match tokio::time::timeout(std::time::Duration::from_secs(1), link.send_control(&close))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%destination, error = %error, "best-effort circuit CLOSE failed during hard revoke")
                }
                Err(_) => {
                    tracing::debug!(%destination, "best-effort circuit CLOSE timed out during hard revoke")
                }
            }
        });
    }
}
