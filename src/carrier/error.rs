use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CarrierError {
    #[error("local RFC-0017 admission rejected")]
    AdmissionRejected,
    #[error("control stream send timed out")]
    ControlStreamTimeout,
    #[error("datagram queue would block")]
    WouldBlock,
    #[error("QUIC DATAGRAM is too large ({size} bytes; limit {limit} bytes)")]
    DatagramTooLarge { size: usize, limit: usize },
    #[error("QUIC endpoint closed")]
    EndpointClosed,
    #[error("QUIC error: {0}")]
    Quinn(#[from] quinn::ConnectionError),
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("read error: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("identity error: {0}")]
    Identity(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("local carrier I/O error (errno {0})")]
    LocalIo(i32),
    #[error("certificate error: {0}")]
    Certificate(String),
    #[error("incoming QUIC connection from {remote} failed during {stage}: {reason}")]
    InboundHandshake {
        remote: SocketAddr,
        stage: &'static str,
        reason: String,
    },
}

impl CarrierError {
    pub(super) fn is_local_datagram_rejection(&self) -> bool {
        matches!(
            self,
            Self::AdmissionRejected | Self::WouldBlock | Self::DatagramTooLarge { .. }
        )
    }
}
