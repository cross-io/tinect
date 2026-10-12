//! The small outbound capability used by Circuit state.
//!
//! A circuit only needs identity, instance and bounded send operations.  The
//! carrier implementation adapts its richer Link object to this interface so
//! circuit bindings do not retain transport-specific state in their public
//! shape.

use crate::control::ControlMessage;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;

pub type LinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), LinkError>> + Send + 'a>>;
pub type LinkRef = Arc<dyn LinkHandle>;
pub type LinkDirectoryRef = Arc<dyn LinkDirectory>;

/// Non-wire lifecycle token for one authenticated Link instance.
///
/// A waiter keeps this token until its result is consumed.  Revoking the
/// token invalidates waiters that race with Link teardown without requiring a
/// process-lifetime set of every Link instance that has ever existed.
#[derive(Clone, Debug)]
pub struct LinkToken(Arc<AtomicBool>);

impl Default for LinkToken {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl LinkToken {
    pub fn is_active(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LinkError {
    #[error("local control or datagram admission rejected")]
    AdmissionRejected,
    #[error("control stream send timed out")]
    ControlStreamTimeout,
    #[error("datagram queue would block")]
    WouldBlock,
    #[error("datagram is too large ({size} bytes; limit {limit} bytes)")]
    DatagramTooLarge { size: usize, limit: usize },
    #[error("link endpoint closed")]
    EndpointClosed,
    #[error("link transport error: {0}")]
    Transport(String),
}

pub trait LinkHandle: Send + Sync {
    fn peer_name(&self) -> &str;
    fn peer_identity(&self) -> &str;
    fn instance(&self) -> u64;
    fn is_healthy(&self) -> bool;
    /// Report a forward-path send outcome back to transport health. The
    /// dataplane owns send-gate decisions; the carrier owns the underlying
    /// health signal, so this is the only health write the trait exposes.
    fn set_healthy(&self, healthy: bool);
    /// Rate-limited gate for dataplane warnings. Returns true at most once
    /// per second per Link so a failing peer cannot spam the log.
    fn should_log_dataplane_warning(&self) -> bool;
    /// Whether the underlying transport endpoint is closed. A closed Link
    /// must never be revived by a stale health-reset timer.
    fn is_closed(&self) -> bool;
    fn send_forward(&self, frame: &[u8]) -> Result<(), LinkError>;
    fn send_control<'a>(&'a self, message: &'a ControlMessage) -> LinkFuture<'a>;
}

pub trait LinkDirectory: Send + Sync {
    fn by_peer(&self, peer_identity: &str) -> Option<LinkRef>;
    fn by_instance(&self, instance: u64) -> Option<LinkRef>;
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FakeLink {
        peer: String,
        identity: String,
        instance: u64,
        healthy: AtomicBool,
        fail_forward: AtomicBool,
        fail_control: AtomicBool,
    }

    impl FakeLink {
        fn new(instance: u64) -> Self {
            Self {
                peer: "relay".into(),
                identity: "relay-identity".into(),
                instance,
                healthy: AtomicBool::new(true),
                fail_forward: AtomicBool::new(false),
                fail_control: AtomicBool::new(false),
            }
        }
    }

    impl LinkHandle for FakeLink {
        fn peer_name(&self) -> &str {
            &self.peer
        }

        fn peer_identity(&self) -> &str {
            &self.identity
        }

        fn instance(&self) -> u64 {
            self.instance
        }

        fn is_healthy(&self) -> bool {
            self.healthy.load(Ordering::Acquire)
        }

        fn set_healthy(&self, healthy: bool) {
            self.healthy.store(healthy, Ordering::Release);
        }

        fn should_log_dataplane_warning(&self) -> bool {
            true
        }

        fn is_closed(&self) -> bool {
            false
        }

        fn send_forward(&self, _frame: &[u8]) -> Result<(), LinkError> {
            if self.fail_forward.load(Ordering::Acquire) {
                Err(LinkError::AdmissionRejected)
            } else {
                Ok(())
            }
        }

        fn send_control<'a>(&'a self, _message: &'a ControlMessage) -> LinkFuture<'a> {
            let result = if self.fail_control.load(Ordering::Acquire) {
                Err(LinkError::ControlStreamTimeout)
            } else {
                Ok(())
            };
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn fake_handle_exposes_only_small_link_capabilities() {
        let link = FakeLink::new(7);
        let ping = ControlMessage::Ping;
        assert_eq!(link.peer_name(), "relay");
        assert_eq!(link.peer_identity(), "relay-identity");
        assert_eq!(link.instance(), 7);
        assert!(link.is_healthy());
        assert!(link.send_forward(&[1, 2, 3]).is_ok());
        link.fail_forward.store(true, Ordering::Release);
        assert_eq!(link.send_forward(&[]), Err(LinkError::AdmissionRejected));
        link.send_control(&ping).await.unwrap();
        link.fail_control.store(true, Ordering::Release);
        assert_eq!(
            link.send_control(&ping).await,
            Err(LinkError::ControlStreamTimeout)
        );
        link.healthy.store(false, Ordering::Release);
        assert!(!link.is_healthy());
    }
}
