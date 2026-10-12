//! Bounded OPEN retry delays with deterministic jitter.
use super::*;
/// Bounded per-circuit OPEN retry with deterministic jitter. Different
/// destinations do not synchronize retries after a relay reconnects, while
/// a test can still reproduce the sequence exactly.
pub(crate) fn circuit_open_retry_delay(destination: &str, attempt: u32) -> std::time::Duration {
    let base = 250_u64.saturating_mul(1_u64 << attempt.min(8)).min(5_000);
    let spread = (base / 10).max(1);
    let seed = reconnect_jitter_seed(destination, "circuit-open");
    let range = spread.saturating_mul(2).saturating_add(1);
    let offset = seed.wrapping_add(u64::from(attempt).wrapping_mul(0x9e3779b97f4a7c15)) % range;
    std::time::Duration::from_millis(base.saturating_sub(spread).saturating_add(offset))
}

pub(crate) fn nonretryable_rejection_wait(
    rejection: &mut Option<(tinect::reconcile::CircuitIdentity, Instant)>,
    preferred: Option<&tinect::reconcile::CircuitIdentity>,
    now: Instant,
) -> Option<std::time::Duration> {
    let (identity, retry_at) = rejection.as_ref()?;
    if preferred != Some(identity) {
        *rejection = None;
        return None;
    }
    let delay = retry_at.checked_duration_since(now);
    if delay.is_none() {
        *rejection = None;
    }
    delay
}
