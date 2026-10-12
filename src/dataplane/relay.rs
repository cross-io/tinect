//! Opaque relay forwarding over circuit labels.

use crate::{
    carrier::CarrierError,
    circuit::{CircuitId, LabelTable},
    crypto,
};
use tokio::sync::mpsc;

pub async fn relay_once(
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    labels: &std::sync::RwLock<LabelTable>,
) -> Result<(), CarrierError> {
    match relay_once_with_feedback(receiver, labels).await? {
        Some(_) => Err(CarrierError::Protocol("unknown circuit label".into())),
        None => Ok(()),
    }
}

/// Relay one opaque frame and return its CircuitId when the local label table
/// has no binding.  The caller can turn that classification failure into an
/// authenticated upstream feedback message without exposing the payload.
pub async fn relay_once_with_feedback(
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    labels: &std::sync::RwLock<LabelTable>,
) -> Result<Option<CircuitId>, CarrierError> {
    let payload = receiver
        .recv()
        .await
        .ok_or_else(|| CarrierError::Protocol("physical payload dispatcher stopped".into()))?;
    let circuit_id = crypto::frame_circuit_id(payload.as_ref())
        .map_err(|e| CarrierError::Protocol(format!("invalid forwarded frame: {e}")))?;
    let Some(binding) = labels.read().expect("relay label lock").forward(circuit_id) else {
        return Ok(Some(circuit_id));
    };
    // The relay binding authenticates the circuit and owns the next hop, but
    // never caches an end-to-end OPEN MTU.  The outgoing carrier performs the
    // exact current wire-length preflight and remains the final authority.
    binding.outgoing.send_forward(payload.as_ref())?;
    Ok(None)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        control::ControlMessage,
        link::{LinkError, LinkFuture, LinkHandle, LinkRef},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    struct TestLink {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        fail_forward: AtomicBool,
    }

    impl LinkHandle for TestLink {
        fn peer_name(&self) -> &str {
            "relay-test"
        }

        fn peer_identity(&self) -> &str {
            "relay-test-identity"
        }

        fn instance(&self) -> u64 {
            1
        }

        fn is_healthy(&self) -> bool {
            true
        }

        fn set_healthy(&self, _healthy: bool) {}

        fn should_log_dataplane_warning(&self) -> bool {
            true
        }

        fn is_closed(&self) -> bool {
            false
        }

        fn send_forward(&self, frame: &[u8]) -> Result<(), LinkError> {
            if self.fail_forward.load(Ordering::Acquire) {
                return Err(LinkError::AdmissionRejected);
            }
            self.sent
                .lock()
                .expect("test link lock")
                .push(frame.to_vec());
            Ok(())
        }

        fn send_control<'a>(&'a self, _message: &'a ControlMessage) -> LinkFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    fn encrypted_frame(circuit_id: CircuitId) -> Vec<u8> {
        let mut sender = crate::crypto::SenderSession::from_key(
            circuit_id,
            chacha20poly1305::Key::from([7; 32]),
        );
        sender.encrypt(b"opaque").unwrap().to_vec()
    }

    #[tokio::test]
    async fn relay_reports_closed_receivers_and_truncated_frames() {
        let (tx, mut receiver) = mpsc::channel(1);
        drop(tx);
        assert!(matches!(
            relay_once_with_feedback(&mut receiver, &std::sync::RwLock::new(LabelTable::default()))
                .await,
            Err(CarrierError::Protocol(message))
                if message == "physical payload dispatcher stopped"
        ));

        let (tx, mut receiver) = mpsc::channel(1);
        tx.send(vec![0; 15]).await.unwrap();
        assert!(matches!(
            relay_once_with_feedback(&mut receiver, &std::sync::RwLock::new(LabelTable::default()))
                .await,
            Err(CarrierError::Protocol(message))
                if message == "invalid forwarded frame: encrypted frame is truncated"
        ));
    }

    #[tokio::test]
    async fn relay_once_classifies_unknown_labels() {
        let circuit_id = CircuitId([3; 16]);
        let (tx, mut receiver) = mpsc::channel(1);
        tx.send(encrypted_frame(circuit_id)).await.unwrap();

        let labels = std::sync::RwLock::new(LabelTable::default());
        assert!(matches!(
            relay_once(&mut receiver, &labels).await,
            Err(CarrierError::Protocol(message)) if message == "unknown circuit label"
        ));
    }

    #[tokio::test]
    async fn relay_forwards_bound_frames_and_propagates_send_errors() {
        let circuit_id = CircuitId([4; 16]);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let outgoing: LinkRef = Arc::new(TestLink {
            sent: sent.clone(),
            fail_forward: AtomicBool::new(false),
        });
        assert_eq!(outgoing.peer_name(), "relay-test");
        assert_eq!(outgoing.peer_identity(), "relay-test-identity");
        assert_eq!(outgoing.instance(), 1);
        assert!(outgoing.is_healthy());
        outgoing.send_control(&ControlMessage::Ping).await.unwrap();
        let mut labels = LabelTable::default();
        labels.install(circuit_id, outgoing.clone()).unwrap();
        let labels = std::sync::RwLock::new(labels);

        let frame = encrypted_frame(circuit_id);
        let (tx, mut receiver) = mpsc::channel(1);
        tx.send(frame.clone()).await.unwrap();
        assert!(matches!(
            relay_once_with_feedback(&mut receiver, &labels).await,
            Ok(None)
        ));
        assert_eq!(sent.lock().unwrap().as_slice(), &[frame]);

        let failing = Arc::new(TestLink {
            sent: Arc::new(Mutex::new(Vec::new())),
            fail_forward: AtomicBool::new(true),
        });
        let mut labels = LabelTable::default();
        labels.install(circuit_id, failing).unwrap();
        let labels = std::sync::RwLock::new(labels);
        let (tx, mut receiver) = mpsc::channel(1);
        tx.send(encrypted_frame(circuit_id)).await.unwrap();
        assert!(matches!(
            relay_once_with_feedback(&mut receiver, &labels).await,
            Err(CarrierError::AdmissionRejected)
        ));
    }
}
