//! Preferred-path migration status reporting.
use super::*;
pub(crate) fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) async fn update_migration_status(
    state: &Arc<tokio::sync::RwLock<DaemonState>>,
    config: &Config,
    destination: &str,
    preferred_path: &[String],
    migration_state: MigrationState,
    started_at: Option<u64>,
    error: Option<String>,
) {
    if let Some(circuit) = state
        .write()
        .await
        .status
        .circuits
        .iter_mut()
        .find(|circuit| circuit.destination == destination)
    {
        circuit.migration_state = migration_state;
        circuit.preferred_path = preferred_path.to_vec();
        circuit.preferred_path_names = preferred_path
            .iter()
            .map(|identity| observable_name(config, identity))
            .collect();
        circuit.migration_started_at = started_at;
        circuit.migration_last_error = error;
    }
}

pub(crate) async fn log_migration_failure(
    config: &Config,
    destination: &str,
    opens: &dataplane::CircuitOpenManager,
    reason: &str,
) {
    let Some((preferred, Some(started), _)) = opens.migration_snapshot(destination).await else {
        return;
    };
    let current = opens
        .active_for_destination(destination)
        .await
        .map(|active| display_path(config, &active.path))
        .unwrap_or_else(|| "<none>".into());
    tracing::warn!(
        destination = %destination,
        current_path = %current,
        preferred_path = %display_path(config, &preferred.ordered_path),
        migration_started_at = unix_timestamp_secs().saturating_sub(started.elapsed().as_secs()),
        reason = %reason,
        "preferred path migration attempt failed"
    );
}
