#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Tinect's policy and control-plane core.  Network device manipulation is
//! deliberately separate from these deterministic, testable decisions.
pub mod carrier;
pub mod circuit;
pub mod config;
pub mod control;
pub mod crypto;
pub mod dataplane;
pub mod dns;
pub mod fake_ip;
pub mod fec;
pub mod identity;
pub mod link;
pub mod mtu;
pub mod observability;
pub mod physical;
pub mod platform;
pub mod policy;
pub mod priority;
pub mod reconcile;
pub mod return_path;
pub mod route_sets;
pub mod routing;
pub mod runtime;
pub mod status;
pub mod timing;
pub mod topology;
pub mod wire;

#[cfg(all(test, target_os = "linux"))]
#[path = "privileged_network_tests.rs"]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_support;
