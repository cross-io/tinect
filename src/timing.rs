//! Process-wide timing policy.
//!
//! Production values are fixed. Privileged integration tests may build with
//! `integration-test-timing` and select one named profile through
//! `TINECT_TEST_TIMING_PROFILE`; arbitrary multipliers are deliberately not
//! supported because independent recovery mechanisms must retain explicit
//! ordering.

use std::{sync::OnceLock, time::Duration};

pub const TEST_TIMING_PROFILE_ENV: &str = "TINECT_TEST_TIMING_PROFILE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimingProfile {
    pub name: &'static str,
    pub circuit_lease: Duration,
    pub circuit_renew_interval: Duration,
    pub lease_refresh_throttle: Duration,
    pub topology_advertisement_ttl_secs: u64,
    pub quicp_handshake_timeout: Duration,
    pub quicp_established_idle_timeout: Duration,
    pub return_flow_ttl: Duration,
    pub no_session_feedback_ttl: Duration,
    pub bare_pmtu_upward_reprobe_interval: Duration,
    pub topology_snapshot_reassembly_timeout: Duration,
    pub topology_snapshot_ack_timeout: Duration,
    pub min_topology_snapshot_request_interval: Duration,
}

const PRODUCTION: TimingProfile = TimingProfile {
    name: "production",
    circuit_lease: Duration::from_secs(12 * 60 * 60),
    circuit_renew_interval: Duration::from_secs(30),
    lease_refresh_throttle: Duration::from_secs(30),
    topology_advertisement_ttl_secs: 50,
    quicp_handshake_timeout: Duration::from_secs(10),
    quicp_established_idle_timeout: Duration::from_secs(5 * 60),
    return_flow_ttl: Duration::from_secs(24 * 60 * 60),
    no_session_feedback_ttl: Duration::from_secs(60),
    bare_pmtu_upward_reprobe_interval: Duration::from_secs(60),
    topology_snapshot_reassembly_timeout: Duration::from_secs(10),
    topology_snapshot_ack_timeout: Duration::from_secs(10),
    min_topology_snapshot_request_interval: Duration::from_secs(10),
};

#[cfg(any(feature = "integration-test-timing", test))]
const CIRCUIT_FAST: TimingProfile = TimingProfile {
    name: "circuit-fast",
    circuit_lease: Duration::from_secs(8),
    circuit_renew_interval: Duration::from_secs(2),
    lease_refresh_throttle: Duration::from_secs(1),
    ..PRODUCTION
};

#[cfg(any(feature = "integration-test-timing", test))]
const MAINTENANCE_FAST: TimingProfile = TimingProfile {
    name: "maintenance-fast",
    quicp_handshake_timeout: Duration::from_secs(2),
    quicp_established_idle_timeout: Duration::from_secs(6),
    return_flow_ttl: Duration::from_secs(6),
    no_session_feedback_ttl: Duration::from_secs(2),
    bare_pmtu_upward_reprobe_interval: Duration::from_secs(3),
    ..PRODUCTION
};

#[cfg(any(feature = "integration-test-timing", test))]
const TOPOLOGY_FAST: TimingProfile = TimingProfile {
    name: "topology-fast",
    topology_advertisement_ttl_secs: 6,
    topology_snapshot_reassembly_timeout: Duration::from_secs(2),
    topology_snapshot_ack_timeout: Duration::from_secs(2),
    min_topology_snapshot_request_interval: Duration::from_secs(2),
    ..PRODUCTION
};

static ACTIVE: OnceLock<TimingProfile> = OnceLock::new();

pub fn initialize() -> Result<&'static TimingProfile, String> {
    if let Some(active) = ACTIVE.get() {
        return Ok(active);
    }
    let selected = selected_from_environment()?;
    let _ = ACTIVE.set(selected);
    Ok(ACTIVE.get().expect("timing profile initialized"))
}

pub fn active() -> &'static TimingProfile {
    initialize().unwrap_or_else(|error| panic!("invalid integration-test timing: {error}"))
}

#[cfg(any(feature = "integration-test-timing", test))]
fn profile_named(name: &str) -> Result<TimingProfile, String> {
    let profile = match name {
        "production" => PRODUCTION,
        "circuit-fast" => CIRCUIT_FAST,
        "maintenance-fast" => MAINTENANCE_FAST,
        "topology-fast" => TOPOLOGY_FAST,
        _ => {
            return Err(format!(
                "unknown {TEST_TIMING_PROFILE_ENV} value {name:?}; expected production, circuit-fast, maintenance-fast, or topology-fast"
            ));
        }
    };
    validate(profile)?;
    Ok(profile)
}

#[cfg(any(feature = "integration-test-timing", test))]
fn validate(profile: TimingProfile) -> Result<(), String> {
    if profile.circuit_renew_interval >= profile.circuit_lease {
        return Err(format!(
            "profile {} must renew before its circuit lease expires",
            profile.name
        ));
    }
    if profile.lease_refresh_throttle >= profile.circuit_lease {
        return Err(format!(
            "profile {} must refresh traffic before its circuit lease expires",
            profile.name
        ));
    }
    if profile.topology_advertisement_ttl_secs < 2 {
        return Err(format!(
            "profile {} topology advertisement TTL must leave room for a positive keepalive interval",
            profile.name
        ));
    }
    Ok(())
}

#[cfg(feature = "integration-test-timing")]
fn selected_from_environment() -> Result<TimingProfile, String> {
    match std::env::var(TEST_TIMING_PROFILE_ENV) {
        Ok(name) => profile_named(&name),
        Err(std::env::VarError::NotPresent) => Ok(PRODUCTION),
        Err(error) => Err(format!("cannot read {TEST_TIMING_PROFILE_ENV}: {error}")),
    }
}

#[cfg(not(feature = "integration-test-timing"))]
fn selected_from_environment() -> Result<TimingProfile, String> {
    Ok(PRODUCTION)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_profiles_preserve_lifecycle_invariants() {
        for name in [
            "production",
            "circuit-fast",
            "maintenance-fast",
            "topology-fast",
        ] {
            let profile = profile_named(name).unwrap();
            assert!(profile.circuit_renew_interval < profile.circuit_lease);
            assert!(profile.lease_refresh_throttle < profile.circuit_lease);
        }
    }

    #[test]
    fn arbitrary_timing_profile_is_rejected() {
        assert!(profile_named("everything-divided-by-ten").is_err());
    }

    #[test]
    fn invalid_lifecycle_orderings_are_rejected() {
        let mut profile = PRODUCTION;
        profile.circuit_renew_interval = profile.circuit_lease;
        assert!(validate(profile).is_err());

        let mut profile = PRODUCTION;
        profile.lease_refresh_throttle = profile.circuit_lease;
        assert!(validate(profile).is_err());

        let mut profile = PRODUCTION;
        profile.topology_advertisement_ttl_secs = 1;
        assert!(validate(profile).is_err());
    }
}
