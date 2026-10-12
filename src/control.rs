//! Binary QUIC control-plane messages.
use crate::{
    circuit::{CircuitId, OpenRequest},
    identity::{decode_public, encode_public},
    topology::LinkStateAdvertisement,
    wire::{self, Reader, Writer},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signer, Verifier};

pub const MAX_TOPOLOGY_SYNC_CHUNK_LSAS: usize = 512;
pub const CIRCUIT_UNKNOWN_SESSION_REASON: u16 = 2;
pub const CIRCUIT_RENEW_REJECTED_REASON: u16 = 3;
/// `CircuitBroken` reason sent when an outbound Link instance closed and the
/// relay binding for it was reclaimed.
pub const CIRCUIT_BROKEN_REASON_LINK_CLOSED: u16 = 1;
/// `CircuitBroken` reason sent when a relay cannot deliver a Renew/RenewAck
/// to its next hop and aborts the binding.
pub const CIRCUIT_BROKEN_REASON_RELAY_FAILURE: u16 = 7;

#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// Reliable topology protocol defined by RFC-0016. A QUIC uni stream
    /// carries exactly one of these messages.
    TopologySync {
        mode: TopologySyncMode,
        sync_id: u64,
        chunk_index: u16,
        chunk_count: u16,
        advertisements: Vec<LinkStateAdvertisement>,
    },
    TopologySyncAck {
        sync_id: u64,
    },
    TopologySyncRequest {
        reason: u16,
    },
    Open(OpenRequest),
    OpenAck {
        circuit_id: CircuitId,
        public_key: String,
        signature: String,
    },
    OpenReject {
        circuit_id: CircuitId,
        retryable: bool,
        reason_code: u16,
        public_key: String,
        signature: String,
    },
    CircuitClose {
        circuit_id: CircuitId,
        counter: u64,
        reason_code: u16,
        public_key: String,
        signature: String,
    },
    CircuitRenew {
        circuit_id: CircuitId,
        counter: u64,
        public_key: String,
        signature: String,
    },
    CircuitRenewAck {
        circuit_id: CircuitId,
        counter: u64,
        public_key: String,
        signature: String,
    },
    CircuitBroken {
        circuit_id: CircuitId,
        reason_code: u16,
        public_key: String,
        signature: String,
    },
    Ping,
    Pong,
    /// Link-local datagram loss feedback. This message is never relayed
    /// through a circuit or topology path.
    FecReport(crate::fec::FecReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologySyncMode {
    Snapshot,
    Delta,
}

impl TopologySyncMode {
    fn encode(self) -> u8 {
        match self {
            Self::Snapshot => 0,
            Self::Delta => 1,
        }
    }

    fn decode(value: u8) -> Result<Self, wire::Error> {
        match value {
            0 => Ok(Self::Snapshot),
            1 => Ok(Self::Delta),
            _ => Err(wire::Error::Truncated),
        }
    }
}

impl ControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>, wire::Error> {
        let (kind, body) = match self {
            Self::TopologySync {
                mode,
                sync_id,
                chunk_index,
                chunk_count,
                advertisements,
            } => {
                if *chunk_count == 0 || *chunk_index >= *chunk_count {
                    return Err(wire::Error::Truncated);
                }
                if matches!(mode, TopologySyncMode::Delta)
                    && (*chunk_count != 1 || *chunk_index != 0)
                {
                    return Err(wire::Error::Truncated);
                }
                if advertisements.len() > MAX_TOPOLOGY_SYNC_CHUNK_LSAS {
                    return Err(wire::Error::Length);
                }
                let mut out = Writer::new();
                out.u8(mode.encode());
                out.u64(*sync_id);
                out.u16(*chunk_index);
                out.u16(*chunk_count);
                out.u16(u16::try_from(advertisements.len()).map_err(|_| wire::Error::Length)?);
                for advertisement in advertisements {
                    advertisement.encode_wire(&mut out)?;
                }
                (25, out.finish())
            }
            Self::TopologySyncAck { sync_id } => {
                let mut out = Writer::new();
                out.u64(*sync_id);
                (26, out.finish())
            }
            Self::TopologySyncRequest { reason } => {
                let mut out = Writer::new();
                out.u16(*reason);
                (27, out.finish())
            }
            Self::Open(request) => (16, request.encode_body()?),
            Self::OpenAck {
                circuit_id,
                public_key,
                signature,
            } => {
                let mut out = Writer::new();
                out.bytes(&circuit_id.0);
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(public_key)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(signature)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                (17, out.finish())
            }
            Self::OpenReject {
                circuit_id,
                retryable,
                reason_code,
                public_key,
                signature,
            } => {
                let mut out = Writer::new();
                out.bytes(&circuit_id.0);
                out.u8(*retryable as u8);
                out.u16(*reason_code);
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(public_key)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(signature)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                (18, out.finish())
            }
            Self::Ping => (19, Vec::new()),
            Self::Pong => (20, Vec::new()),
            Self::FecReport(report) => {
                if report.report_id == 0
                    || report.samples == 0
                    || report.loss_ppm > 1_000_000
                    || report.burst_milli < 1_000
                {
                    return Err(wire::Error::Truncated);
                }
                let mut out = Writer::new();
                out.u64(report.report_id);
                out.u32(report.samples);
                out.u32(report.loss_ppm);
                out.u16(report.burst_milli);
                (29, out.finish())
            }
            Self::CircuitClose {
                circuit_id,
                counter,
                reason_code,
                public_key,
                signature,
            } => {
                let mut out = Writer::new();
                out.bytes(&circuit_id.0);
                out.u64(*counter);
                out.u16(*reason_code);
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(public_key)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(signature)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                (21, out.finish())
            }
            Self::CircuitRenew {
                circuit_id,
                counter,
                public_key,
                signature,
            }
            | Self::CircuitRenewAck {
                circuit_id,
                counter,
                public_key,
                signature,
            } => {
                let mut out = Writer::new();
                out.bytes(&circuit_id.0);
                out.u64(*counter);
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(public_key)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(signature)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                (
                    if matches!(self, Self::CircuitRenew { .. }) {
                        22
                    } else {
                        23
                    },
                    out.finish(),
                )
            }
            Self::CircuitBroken {
                circuit_id,
                reason_code,
                public_key,
                signature,
            } => {
                let mut out = Writer::new();
                out.bytes(&circuit_id.0);
                out.u16(*reason_code);
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(public_key)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                out.bytes(
                    &STANDARD_NO_PAD
                        .decode(signature)
                        .map_err(|_| wire::Error::Truncated)?,
                );
                (24, out.finish())
            }
        };
        wire::encode_message(kind, body)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, wire::Error> {
        let (kind, body) = wire::decode_message(bytes)?;
        let mut input = Reader::new(body);
        let message = match kind {
            25 => {
                let mode = TopologySyncMode::decode(input.u8()?)?;
                let sync_id = input.u64()?;
                let chunk_index = input.u16()?;
                let chunk_count = input.u16()?;
                if chunk_count == 0 || chunk_index >= chunk_count {
                    return Err(wire::Error::Truncated);
                }
                if matches!(mode, TopologySyncMode::Delta) && (chunk_count != 1 || chunk_index != 0)
                {
                    return Err(wire::Error::Truncated);
                }
                let count = usize::from(input.u16()?);
                if count > MAX_TOPOLOGY_SYNC_CHUNK_LSAS {
                    return Err(wire::Error::Length);
                }
                let mut advertisements = Vec::with_capacity(count);
                for _ in 0..count {
                    advertisements.push(LinkStateAdvertisement::decode_wire(&mut input)?);
                }
                Self::TopologySync {
                    mode,
                    sync_id,
                    chunk_index,
                    chunk_count,
                    advertisements,
                }
            }
            26 => Self::TopologySyncAck {
                sync_id: input.u64()?,
            },
            27 => Self::TopologySyncRequest {
                reason: input.u16()?,
            },
            16 => Self::Open(OpenRequest::decode_body(body)?),
            17 => Self::OpenAck {
                circuit_id: CircuitId(input.fixed()?),
                public_key: STANDARD_NO_PAD.encode(input.fixed::<32>()?),
                signature: STANDARD_NO_PAD.encode(input.fixed::<64>()?),
            },
            18 => Self::OpenReject {
                circuit_id: CircuitId(input.fixed()?),
                retryable: input.bool()?,
                reason_code: input.u16()?,
                public_key: STANDARD_NO_PAD.encode(input.fixed::<32>()?),
                signature: STANDARD_NO_PAD.encode(input.fixed::<64>()?),
            },
            19 => Self::Ping,
            20 => Self::Pong,
            29 => {
                let report = crate::fec::FecReport {
                    report_id: input.u64()?,
                    samples: input.u32()?,
                    loss_ppm: input.u32()?,
                    burst_milli: input.u16()?,
                };
                if report.report_id == 0
                    || report.samples == 0
                    || report.loss_ppm > 1_000_000
                    || report.burst_milli < 1_000
                {
                    return Err(wire::Error::Truncated);
                }
                Self::FecReport(report)
            }
            21 => Self::CircuitClose {
                circuit_id: CircuitId(input.fixed()?),
                counter: input.u64()?,
                reason_code: input.u16()?,
                public_key: STANDARD_NO_PAD.encode(input.fixed::<32>()?),
                signature: STANDARD_NO_PAD.encode(input.fixed::<64>()?),
            },
            22 | 23 => {
                let circuit_id = CircuitId(input.fixed()?);
                let counter = input.u64()?;
                let public_key = STANDARD_NO_PAD.encode(input.fixed::<32>()?);
                let signature = STANDARD_NO_PAD.encode(input.fixed::<64>()?);
                if kind == 22 {
                    Self::CircuitRenew {
                        circuit_id,
                        counter,
                        public_key,
                        signature,
                    }
                } else {
                    Self::CircuitRenewAck {
                        circuit_id,
                        counter,
                        public_key,
                        signature,
                    }
                }
            }
            24 => Self::CircuitBroken {
                circuit_id: CircuitId(input.fixed()?),
                reason_code: input.u16()?,
                public_key: STANDARD_NO_PAD.encode(input.fixed::<32>()?),
                signature: STANDARD_NO_PAD.encode(input.fixed::<64>()?),
            },
            _ => return Err(wire::Error::Truncated),
        };
        if kind != 16 {
            input.finish()?;
        }
        Ok(message)
    }

    pub fn open_ack(identity: &ed25519_dalek::SigningKey, circuit_id: CircuitId) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = sign_result(identity, 17, circuit_id, false, 0, &public_key);
        Self::OpenAck {
            circuit_id,
            public_key,
            signature,
        }
    }

    pub fn open_reject(
        identity: &ed25519_dalek::SigningKey,
        circuit_id: CircuitId,
        retryable: bool,
        reason_code: u16,
    ) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = sign_result(
            identity,
            18,
            circuit_id,
            retryable,
            reason_code,
            &public_key,
        );
        Self::OpenReject {
            circuit_id,
            retryable,
            reason_code,
            public_key,
            signature,
        }
    }

    pub fn verify_result(&self) -> bool {
        let (kind, circuit_id, retryable, reason_code, public_key, signature) = match self {
            Self::OpenAck {
                circuit_id,
                public_key,
                signature,
            } => (17, *circuit_id, false, 0, public_key, signature),
            Self::OpenReject {
                circuit_id,
                retryable,
                reason_code,
                public_key,
                signature,
            } => (
                18,
                *circuit_id,
                *retryable,
                *reason_code,
                public_key,
                signature,
            ),
            _ => return false,
        };
        let Ok(key) = decode_public(public_key) else {
            return false;
        };
        let Ok(signature) = STANDARD_NO_PAD.decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        key.verify(
            &result_bytes(kind, circuit_id, retryable, reason_code, public_key),
            &signature,
        )
        .is_ok()
    }

    pub fn circuit_close(
        identity: &ed25519_dalek::SigningKey,
        circuit_id: CircuitId,
        counter: u64,
        reason_code: u16,
    ) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = STANDARD_NO_PAD.encode(
            identity
                .sign(&close_bytes(
                    21,
                    circuit_id,
                    counter,
                    reason_code,
                    &public_key,
                ))
                .to_bytes(),
        );
        Self::CircuitClose {
            circuit_id,
            counter,
            reason_code,
            public_key,
            signature,
        }
    }

    pub fn verify_close(&self) -> bool {
        let Self::CircuitClose {
            circuit_id,
            counter,
            reason_code,
            public_key,
            signature,
        } = self
        else {
            return false;
        };
        let Ok(key) = decode_public(public_key) else {
            return false;
        };
        let Ok(signature) = STANDARD_NO_PAD.decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        key.verify(
            &close_bytes(21, *circuit_id, *counter, *reason_code, public_key),
            &signature,
        )
        .is_ok()
    }

    pub fn circuit_renew(
        identity: &ed25519_dalek::SigningKey,
        circuit_id: CircuitId,
        counter: u64,
    ) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = STANDARD_NO_PAD.encode(
            identity
                .sign(&renew_bytes(22, circuit_id, counter, &public_key))
                .to_bytes(),
        );
        Self::CircuitRenew {
            circuit_id,
            counter,
            public_key,
            signature,
        }
    }
    pub fn circuit_renew_ack(
        identity: &ed25519_dalek::SigningKey,
        circuit_id: CircuitId,
        counter: u64,
    ) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = STANDARD_NO_PAD.encode(
            identity
                .sign(&renew_bytes(23, circuit_id, counter, &public_key))
                .to_bytes(),
        );
        Self::CircuitRenewAck {
            circuit_id,
            counter,
            public_key,
            signature,
        }
    }
    pub fn verify_renew(&self) -> bool {
        let (kind, circuit_id, counter, public_key, signature) = match self {
            Self::CircuitRenew {
                circuit_id,
                counter,
                public_key,
                signature,
            } => (22, *circuit_id, *counter, public_key, signature),
            Self::CircuitRenewAck {
                circuit_id,
                counter,
                public_key,
                signature,
            } => (23, *circuit_id, *counter, public_key, signature),
            _ => return false,
        };
        let Ok(key) = decode_public(public_key) else {
            return false;
        };
        let Ok(signature) = STANDARD_NO_PAD.decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        key.verify(
            &renew_bytes(kind, circuit_id, counter, public_key),
            &signature,
        )
        .is_ok()
    }
    pub fn circuit_broken(
        identity: &ed25519_dalek::SigningKey,
        circuit_id: CircuitId,
        reason_code: u16,
    ) -> Self {
        let public_key = encode_public(&identity.verifying_key());
        let signature = STANDARD_NO_PAD.encode(
            identity
                .sign(&broken_bytes(24, circuit_id, reason_code, &public_key))
                .to_bytes(),
        );
        Self::CircuitBroken {
            circuit_id,
            reason_code,
            public_key,
            signature,
        }
    }
    pub fn verify_broken(&self) -> bool {
        let Self::CircuitBroken {
            circuit_id,
            reason_code,
            public_key,
            signature,
        } = self
        else {
            return false;
        };
        let Ok(key) = decode_public(public_key) else {
            return false;
        };
        let Ok(signature) = STANDARD_NO_PAD.decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        key.verify(
            &broken_bytes(24, *circuit_id, *reason_code, public_key),
            &signature,
        )
        .is_ok()
    }
}

fn result_bytes(
    kind: u8,
    circuit_id: CircuitId,
    retryable: bool,
    reason_code: u16,
    public_key: &str,
) -> Vec<u8> {
    let mut out = Writer::new();
    out.u8(kind);
    out.bytes(&circuit_id.0);
    out.u8(retryable as u8);
    out.u16(reason_code);
    out.bytes(
        &STANDARD_NO_PAD
            .decode(public_key)
            .expect("valid result public key"),
    );
    out.finish()
}
fn sign_result(
    identity: &ed25519_dalek::SigningKey,
    kind: u8,
    circuit_id: CircuitId,
    retryable: bool,
    reason_code: u16,
    public_key: &str,
) -> String {
    STANDARD_NO_PAD.encode(
        identity
            .sign(&result_bytes(
                kind,
                circuit_id,
                retryable,
                reason_code,
                public_key,
            ))
            .to_bytes(),
    )
}
fn close_bytes(
    kind: u8,
    circuit_id: CircuitId,
    counter: u64,
    reason_code: u16,
    public_key: &str,
) -> Vec<u8> {
    let mut out = Writer::new();
    out.u8(kind);
    out.bytes(&circuit_id.0);
    out.u64(counter);
    out.u16(reason_code);
    out.bytes(
        &STANDARD_NO_PAD
            .decode(public_key)
            .expect("valid close public key"),
    );
    out.finish()
}
fn renew_bytes(kind: u8, circuit_id: CircuitId, counter: u64, public_key: &str) -> Vec<u8> {
    let mut out = Writer::new();
    out.u8(kind);
    out.bytes(&circuit_id.0);
    out.u64(counter);
    out.bytes(
        &STANDARD_NO_PAD
            .decode(public_key)
            .expect("valid renew public key"),
    );
    out.finish()
}
fn broken_bytes(kind: u8, circuit_id: CircuitId, reason_code: u16, public_key: &str) -> Vec<u8> {
    let mut out = Writer::new();
    out.u8(kind);
    out.bytes(&circuit_id.0);
    out.u16(reason_code);
    out.bytes(
        &STANDARD_NO_PAD
            .decode(public_key)
            .expect("valid broken public key"),
    );
    out.finish()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_are_binary_and_reject_trailing_bytes() {
        let id = CircuitId([9; 16]);
        let identity = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let encoded = ControlMessage::open_reject(&identity, id, true, 7)
            .encode()
            .unwrap();
        assert_eq!(&encoded[..3], &[18, 0, 115]);
        let ControlMessage::OpenReject {
            circuit_id,
            retryable,
            reason_code,
            ..
        } = ControlMessage::decode(&encoded).unwrap()
        else {
            panic!("wrong control message")
        };
        assert_eq!(circuit_id, id);
        assert!(retryable);
        assert_eq!(reason_code, 7);
        assert!(ControlMessage::decode(&encoded).unwrap().verify_result());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            ControlMessage::decode(&trailing),
            Err(wire::Error::Trailing)
        ));
    }

    #[test]
    fn renew_and_close_are_signed_and_tampering_is_rejected() {
        let identity = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let renew = ControlMessage::circuit_renew(&identity, CircuitId([2; 16]), 1);
        assert!(renew.verify_renew());
        let mut wire = renew.encode().unwrap();
        *wire.last_mut().unwrap() ^= 1;
        assert!(!ControlMessage::decode(&wire).unwrap().verify_renew());
        let close = ControlMessage::circuit_close(&identity, CircuitId([2; 16]), 1, 9);
        assert!(close.verify_close());
        let broken = ControlMessage::circuit_broken(&identity, CircuitId([2; 16]), 9);
        assert!(broken.verify_broken());
        let invalidation = ControlMessage::circuit_broken(&identity, CircuitId([2; 16]), 2);
        assert!(invalidation.verify_broken());
        let decoded = ControlMessage::decode(&invalidation.encode().unwrap()).unwrap();
        let ControlMessage::CircuitBroken {
            circuit_id: decoded_id,
            reason_code: decoded_reason,
            ..
        } = decoded
        else {
            panic!("wrong control message");
        };
        assert_eq!(decoded_id, CircuitId([2; 16]));
        assert_eq!(decoded_reason, 2);
        let mut invalidation_wire = invalidation.encode().unwrap();
        *invalidation_wire.last_mut().unwrap() ^= 1;
        assert!(
            !ControlMessage::decode(&invalidation_wire)
                .unwrap()
                .verify_broken()
        );
    }

    #[test]
    fn signed_control_messages_are_domain_separated_by_wire_kind() {
        let identity = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let circuit_id = CircuitId([44; 16]);
        let ack = ControlMessage::open_ack(&identity, circuit_id);
        let ControlMessage::OpenAck {
            public_key,
            signature,
            ..
        } = ack
        else {
            unreachable!();
        };
        assert!(
            !ControlMessage::OpenReject {
                circuit_id,
                retryable: false,
                reason_code: 0,
                public_key,
                signature,
            }
            .verify_result()
        );

        let renew = ControlMessage::circuit_renew(&identity, circuit_id, 1);
        let ControlMessage::CircuitRenew {
            public_key,
            signature,
            ..
        } = renew
        else {
            unreachable!();
        };
        assert!(
            !ControlMessage::CircuitRenewAck {
                circuit_id,
                counter: 1,
                public_key,
                signature,
            }
            .verify_renew()
        );
    }

    #[test]
    fn reliable_topology_messages_round_trip_and_enforce_chunk_bounds() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let origin = crate::identity::node_id(&key.verifying_key());
        let advertisement = LinkStateAdvertisement::new(origin, &key, 7, 100, vec![]);
        let message = ControlMessage::TopologySync {
            mode: TopologySyncMode::Snapshot,
            sync_id: 9,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![advertisement],
        };
        let encoded = message.encode().unwrap();
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Ok(ControlMessage::TopologySync {
                mode: TopologySyncMode::Snapshot,
                sync_id: 9,
                chunk_index: 0,
                chunk_count: 1,
                ..
            })
        ));
        assert!(
            ControlMessage::TopologySync {
                mode: TopologySyncMode::Delta,
                sync_id: 1,
                chunk_index: 1,
                chunk_count: 2,
                advertisements: vec![],
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn fec_reports_are_bounded_and_round_trip() {
        let report = crate::fec::FecReport {
            report_id: 7,
            samples: 128,
            loss_ppm: 25_000,
            burst_milli: 1_500,
        };
        let ControlMessage::FecReport(decoded) =
            ControlMessage::decode(&ControlMessage::FecReport(report).encode().unwrap()).unwrap()
        else {
            panic!("wrong control message");
        };
        assert_eq!(decoded, report);
        assert!(
            ControlMessage::FecReport(crate::fec::FecReport {
                report_id: 0,
                ..report
            })
            .encode()
            .is_err()
        );
    }

    #[test]
    fn control_codecs_reject_invalid_kinds_bounds_and_signatures() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let origin = crate::identity::node_id(&key.verifying_key());
        let advertisement = LinkStateAdvertisement::new(origin, &key, 1, 100, vec![]);
        let topology = ControlMessage::TopologySync {
            mode: TopologySyncMode::Snapshot,
            sync_id: 1,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![advertisement.clone()],
        };
        let mut invalid_mode = topology.encode().unwrap();
        invalid_mode[3] = 2;
        assert!(matches!(
            ControlMessage::decode(&invalid_mode),
            Err(wire::Error::Truncated)
        ));
        assert!(
            ControlMessage::TopologySync {
                mode: TopologySyncMode::Snapshot,
                sync_id: 1,
                chunk_index: 0,
                chunk_count: 0,
                advertisements: vec![],
            }
            .encode()
            .is_err()
        );
        assert!(
            ControlMessage::TopologySync {
                mode: TopologySyncMode::Snapshot,
                sync_id: 1,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: vec![advertisement; MAX_TOPOLOGY_SYNC_CHUNK_LSAS + 1],
            }
            .encode()
            .is_err()
        );
        let mut invalid_delta = topology.encode().unwrap();
        invalid_delta[3] = TopologySyncMode::Delta.encode();
        invalid_delta[14..16].copy_from_slice(&2_u16.to_be_bytes());
        assert!(ControlMessage::decode(&invalid_delta).is_err());

        let mut invalid_count = topology.encode().unwrap();
        invalid_count[16..18].copy_from_slice(&0_u16.to_be_bytes());
        assert!(ControlMessage::decode(&invalid_count).is_err());
        let mut oversized_count = topology.encode().unwrap();
        oversized_count[16..18].copy_from_slice(
            &(u16::try_from(MAX_TOPOLOGY_SYNC_CHUNK_LSAS + 1).expect("test bound fits in u16"))
                .to_be_bytes(),
        );
        assert!(ControlMessage::decode(&oversized_count).is_err());

        let mut invalid_fec = ControlMessage::FecReport(crate::fec::FecReport {
            report_id: 1,
            samples: 1,
            loss_ppm: 0,
            burst_milli: 1_000,
        })
        .encode()
        .unwrap();
        invalid_fec[3..11].fill(0);
        assert!(ControlMessage::decode(&invalid_fec).is_err());
        assert!(ControlMessage::decode(&wire::encode_message(99, Vec::new()).unwrap()).is_err());

        let id = CircuitId([19; 16]);
        assert!(!ControlMessage::Ping.verify_result());
        assert!(
            !ControlMessage::OpenAck {
                circuit_id: id,
                public_key: "!".into(),
                signature: "!".into(),
            }
            .verify_result()
        );
        let public_key = crate::identity::encode_public(&key.verifying_key());
        assert!(
            !ControlMessage::OpenAck {
                circuit_id: id,
                public_key: public_key.clone(),
                signature: "!".into(),
            }
            .verify_result()
        );
        assert!(
            !ControlMessage::OpenAck {
                circuit_id: id,
                public_key: public_key.clone(),
                signature: "AA".into(),
            }
            .verify_result()
        );

        assert!(!ControlMessage::Ping.verify_close());
        assert!(
            !ControlMessage::CircuitClose {
                circuit_id: id,
                counter: 1,
                reason_code: 1,
                public_key: "!".into(),
                signature: "!".into(),
            }
            .verify_close()
        );
        assert!(
            !ControlMessage::CircuitClose {
                circuit_id: id,
                counter: 1,
                reason_code: 1,
                public_key: public_key.clone(),
                signature: "!".into(),
            }
            .verify_close()
        );
        assert!(
            !ControlMessage::CircuitClose {
                circuit_id: id,
                counter: 1,
                reason_code: 1,
                public_key: public_key.clone(),
                signature: "AA".into(),
            }
            .verify_close()
        );

        assert!(!ControlMessage::Ping.verify_renew());
        assert!(
            !ControlMessage::CircuitRenew {
                circuit_id: id,
                counter: 1,
                public_key: "!".into(),
                signature: "!".into(),
            }
            .verify_renew()
        );
        assert!(
            !ControlMessage::CircuitRenew {
                circuit_id: id,
                counter: 1,
                public_key: public_key.clone(),
                signature: "!".into(),
            }
            .verify_renew()
        );
        assert!(
            !ControlMessage::CircuitRenew {
                circuit_id: id,
                counter: 1,
                public_key: public_key.clone(),
                signature: "AA".into(),
            }
            .verify_renew()
        );

        assert!(!ControlMessage::Ping.verify_broken());
        assert!(
            !ControlMessage::CircuitBroken {
                circuit_id: id,
                reason_code: 1,
                public_key: "!".into(),
                signature: "!".into(),
            }
            .verify_broken()
        );
        assert!(
            !ControlMessage::CircuitBroken {
                circuit_id: id,
                reason_code: 1,
                public_key,
                signature: "!".into(),
            }
            .verify_broken()
        );
        assert!(
            !ControlMessage::CircuitBroken {
                circuit_id: id,
                reason_code: 1,
                public_key: crate::identity::encode_public(&key.verifying_key()),
                signature: "AA".into(),
            }
            .verify_broken()
        );
    }

    #[test]
    fn topology_sync_decode_rejects_zero_chunk_count() {
        let mut body = Writer::new();
        body.u8(TopologySyncMode::Snapshot.encode());
        body.u64(1);
        body.u16(0);
        body.u16(0);
        let encoded = wire::encode_message(25, body.finish()).unwrap();
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(wire::Error::Truncated)
        ));
    }
}
