use super::support::mark_current_link;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tinect::{
    carrier,
    config::LinkHealthConfig,
    dataplane,
    runtime::{LinkRegistry, SharedDaemonState},
};

pub(crate) fn outbound_bind_address(listener: SocketAddr, remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        SocketAddr::new(
            if listener.is_ipv4() {
                listener.ip()
            } else {
                Ipv4Addr::UNSPECIFIED.into()
            },
            0,
        )
    } else {
        SocketAddr::new(
            if listener.is_ipv6() {
                listener.ip()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        )
    }
}

/// Delay retries without allowing an unavailable peer to create a connection
/// storm. The first failures use a short convergence window, then the
/// configured interval becomes the base for exponential backoff. A
/// successfully authenticated Link resets the streak.
pub(crate) fn reconnect_delay(base_secs: u64, failure_streak: u32) -> std::time::Duration {
    const MAX_RECONNECT_DELAY_SECS: u64 = 5;
    let delay = match failure_streak {
        0 => std::time::Duration::ZERO,
        1 => std::time::Duration::from_millis(100),
        2 => std::time::Duration::from_millis(250),
        3 => std::time::Duration::from_millis(500),
        streak => {
            let exponent = streak.saturating_sub(4).min(63);
            let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
            std::time::Duration::from_secs(
                base_secs
                    .saturating_mul(multiplier)
                    .min(MAX_RECONNECT_DELAY_SECS),
            )
        }
    };
    delay.min(std::time::Duration::from_secs(MAX_RECONNECT_DELAY_SECS))
}

pub(crate) fn reconnect_jitter_seed(peer: &str, endpoint: &str) -> u64 {
    peer.bytes()
        .chain([0xff])
        .chain(endpoint.bytes())
        .fold(0xcbf29ce484222325, |hash, byte| {
            hash.wrapping_mul(0x100000001b3)
                .wrapping_add(u64::from(byte))
        })
}

pub(crate) fn reconnect_delay_with_jitter(
    base_secs: u64,
    failure_streak: u32,
    seed: u64,
) -> std::time::Duration {
    let delay = reconnect_delay(base_secs, failure_streak);
    if delay.is_zero() {
        return delay;
    }
    let spread = (delay.as_millis() / 10).max(1);
    let range = spread.saturating_mul(2).saturating_add(1);
    let mixed = seed.wrapping_add(u64::from(failure_streak).wrapping_mul(0x9e3779b97f4a7c15));
    let offset = (u128::from(mixed % u64::try_from(range).unwrap_or(u64::MAX))) as i128
        - i128::try_from(spread).unwrap_or(i128::MAX);
    let millis = (delay.as_millis() as i128 + offset).max(1) as u64;
    std::time::Duration::from_millis(millis)
}

/// Bounds DNS resolution, transport setup, and the authenticated hello so a
/// broken carrier cannot strand the reconnect supervisor in one attempt.
pub(crate) fn outbound_attempt_timeout(_health: &LinkHealthConfig) -> std::time::Duration {
    // A carrier handshake must not occupy the reconnect supervisor for the
    // full idle timeout.  In particular, a lost raw fake-TCP/QUIC handshake
    // otherwise leaves the peer unavailable for several seconds before the
    // supervisor can make a fresh attempt.  Config validation guarantees
    // `idle_timeout_secs > keepalive_secs >= 1`, so the previous
    // `(idle + 5).clamp(1, 5)` expression was constant 5s for every valid
    // configuration; keep that explicit cap and the parameter for call-site
    // stability in case the policy ever becomes configurable.
    std::time::Duration::from_secs(5)
}

/// Install one authenticated QUIC Link per peer. A newly authenticated Link
/// always supersedes the registered instance. This is deliberate: after a
/// peer crash its old QUIC connection can remain idle until its timeout, and
/// retaining it merely because its random LinkId sorts first would reject the
/// peer's recovery connection. The displaced connection is closed after
/// releasing the registry lock; its instance-scoped cleanup cannot affect the
/// replacement.
pub(crate) async fn register_link(links: &LinkRegistry, candidate: Arc<carrier::Link>) -> bool {
    let replaced = {
        let mut registered = links.lock().expect("link registry lock");
        match registered.get(&candidate.peer) {
            Some(current) => {
                let previous = current.clone();
                registered.insert(candidate.peer.clone(), candidate);
                Some(previous)
            }
            None => {
                registered.insert(candidate.peer.clone(), candidate);
                None
            }
        }
    };
    if let Some(link) = replaced {
        link.close("superseded QUIC link");
    }
    true
}

pub(crate) async fn remove_link_if_current(
    links: &LinkRegistry,
    state: &SharedDaemonState,
    peer: &str,
    instance: u64,
    opens: &dataplane::CircuitOpenManager,
) {
    let removed = {
        let mut registered = links.lock().expect("link registry lock");
        if registered
            .get(peer)
            .is_some_and(|current| current.instance() == instance)
        {
            registered.remove(peer);
            true
        } else {
            false
        }
    };
    if removed {
        mark_current_link(
            state,
            links,
            peer,
            instance,
            false,
            Some("QUIC connection closed".into()),
            opens,
        )
        .await;
    }
}
