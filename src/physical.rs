//! RFC-0015 authenticated physical envelopes.
//!
//! Forward frames deliberately keep the end-to-end ciphertext outside the
//! physical AEAD.  Only the circuit metadata is encrypted; the ciphertext is
//! included in the physical AAD, so a relay can carry it unchanged without
//! being able to replace it or pair it with another tag.
use crate::{
    crypto::{self, ReplayWindow},
    identity::node_id_bytes,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, AeadInOut, Payload},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use inout::InOutBuf;
use sha2::Sha256;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

const DOMAIN: &[u8] = b"tinect-physical-payload-v2\0";
const TAG_LEN: usize = 16;
const SEQUENCE_LEN: usize = 8;
const CIRCUIT_METADATA_LEN: usize = 40;
const FORWARD_HEADER_LEN: usize = 1 + SEQUENCE_LEN + CIRCUIT_METADATA_LEN;
pub const FORM_FORWARD: u8 = 0x00;
/// Reserved by RFC-0016. Topology is carried exclusively on authenticated
/// reliable control streams and this physical form is rejected.
pub const FORM_TOPOLOGY: u8 = 0x01;
pub const FORM_PROBE: u8 = 0x02;
pub const FORM_PROBE_ACK: u8 = 0x03;
pub const FORM_KEEPALIVE: u8 = 0x04;
pub const FORM_FEC_SOURCE: u8 = 0x05;
pub const FORM_FEC_REPAIR: u8 = 0x06;
/// Physical tag plus form/sequence and the fixed metadata ciphertext.
pub const FORWARD_OVERHEAD: usize = 1 + SEQUENCE_LEN + TAG_LEN;
/// Upper bound for decoded probe padding. Today's callers are bounded by the
/// DATAGRAM MTU, but an explicit cap keeps future control-stream framing from
/// amplifying an unbounded copy.
pub const MAX_PROBE_PADDING_BYTES: usize = 65535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalPayload {
    Forward(Vec<u8>),
    FecSource {
        transmission_sequence: u32,
        esi: u32,
        frame: Vec<u8>,
    },
    FecRepair {
        transmission_sequence: u32,
        rid: u32,
        first_esi: u32,
        symbol_count: u16,
        vector: Vec<u8>,
    },
    Probe {
        probe_id: u64,
        target_len: u16,
        padding: Vec<u8>,
    },
    ProbeAck {
        probe_id: u64,
        target_len: u16,
    },
    /// Authenticated D1 liveness marker. It carries no topology state.
    Keepalive,
}

impl PhysicalPayload {
    pub fn wire_len(&self) -> Result<usize, PhysicalError> {
        match self {
            Self::Forward(frame) => {
                if frame.len() < crypto::FRAME_OVERHEAD {
                    return Err(PhysicalError::Truncated);
                }
                Ok(FORWARD_OVERHEAD + frame.len())
            }
            Self::FecSource { frame, .. } => {
                if frame.len() < crypto::FRAME_OVERHEAD {
                    return Err(PhysicalError::Truncated);
                }
                Ok(FORWARD_OVERHEAD + frame.len() + 8)
            }
            Self::FecRepair {
                vector,
                symbol_count,
                ..
            } => {
                if *symbol_count == 0 || usize::from(*symbol_count) > crate::fec::MAX_REPAIR_WINDOW
                {
                    return Err(PhysicalError::Encoding("invalid FEC repair count".into()));
                }
                if vector.is_empty() || vector.len() > crate::fec::MAX_SYMBOL_BYTES {
                    return Err(PhysicalError::Encoding("invalid FEC repair vector".into()));
                }
                Ok(1 + SEQUENCE_LEN + 14 + vector.len() + TAG_LEN)
            }
            Self::Probe { padding, .. } => Ok(1 + SEQUENCE_LEN + 10 + padding.len() + TAG_LEN),
            Self::ProbeAck { .. } => Ok(1 + SEQUENCE_LEN + 10 + TAG_LEN),
            Self::Keepalive => Ok(1 + SEQUENCE_LEN + TAG_LEN),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PhysicalError {
    #[error("physical payload is truncated")]
    Truncated,
    #[error("physical payload authentication failed")]
    Authentication,
    #[error("physical payload replayed")]
    Replay,
    #[error("physical payload encoding failed: {0}")]
    Encoding(String),
    #[error("physical payload sequence exhausted")]
    Sequence,
    #[error("invalid physical form {0:#x}")]
    Form(u8),
}

pub struct PhysicalSession {
    send_cipher: ChaCha20Poly1305,
    receive_cipher: ChaCha20Poly1305,
    local_id: [u8; 16],
    peer_id: [u8; 16],
    link_nonce: [u8; 32],
    direction: u8,
    receive_direction: u8,
    send_sequence: AtomicU64,
    replay: Mutex<ReplayWindow>,
}

impl PhysicalSession {
    pub fn new(
        local: &SigningKey,
        peer: &VerifyingKey,
        link_nonce: &[u8],
    ) -> Result<Self, PhysicalError> {
        let nonce: [u8; 32] = link_nonce
            .try_into()
            .map_err(|_| PhysicalError::Encoding("link nonce must be 32 bytes".into()))?;
        let local_public = local.verifying_key();
        let local_id = node_id_bytes(&local_public);
        let peer_id = node_id_bytes(peer);
        let shared = crypto::private_x25519(local).diffie_hellman(
            &crypto::public_x25519(peer).map_err(|e| PhysicalError::Encoding(e.to_string()))?,
        );
        let (first, second, local_first) = if local_public.as_bytes() < peer.as_bytes() {
            (local_public.as_bytes(), peer.as_bytes(), true)
        } else {
            (peer.as_bytes(), local_public.as_bytes(), false)
        };
        let derive = |direction: u8| -> Key {
            let mut info = Vec::with_capacity(32 + 32 + 32 + 1);
            info.extend_from_slice(first);
            info.extend_from_slice(second);
            info.extend_from_slice(&nonce);
            info.push(direction);
            let hkdf = Hkdf::<Sha256>::new(Some(DOMAIN), shared.as_bytes());
            let mut bytes = [0; 32];
            hkdf.expand(&info, &mut bytes).expect("fixed key length");
            Key::from(bytes)
        };
        let direction = if local_first { 0 } else { 1 };
        Ok(Self {
            send_cipher: ChaCha20Poly1305::new(&derive(direction)),
            receive_cipher: ChaCha20Poly1305::new(&derive(1 - direction)),
            local_id,
            peer_id,
            link_nonce: nonce,
            direction,
            receive_direction: 1 - direction,
            send_sequence: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::default()),
        })
    }
    fn next_sequence(&self) -> Result<u64, PhysicalError> {
        loop {
            let current = self.send_sequence.load(Ordering::Relaxed);
            let next = current.checked_add(1).ok_or(PhysicalError::Sequence)?;
            if self
                .send_sequence
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(current);
            }
        }
    }

    /// Exhaust the send sequence space so the next seal deterministically
    /// fails with `PhysicalError::Sequence`.
    #[cfg(test)]
    pub(crate) fn exhaust_send_sequence_for_test(&self) {
        self.send_sequence.store(u64::MAX, Ordering::Relaxed);
    }

    /// Seal an end-to-end encrypted frame for physical forwarding without
    /// taking ownership of it. Forwarders commonly retain the frame for
    /// retry, so accepting a slice avoids an otherwise mandatory full-frame
    /// clone before the physical envelope is built.
    pub fn seal_forward(&self, frame: &[u8]) -> Result<Vec<u8>, PhysicalError> {
        if frame.len() < crypto::FRAME_OVERHEAD {
            return Err(PhysicalError::Truncated);
        }
        let sequence = self.next_sequence()?;
        let ciphertext = &frame[24..frame.len() - TAG_LEN];
        let aad = self.aad(FORM_FORWARD, sequence, ciphertext, self.direction, &[]);
        // The sealed metadata is exactly 40 bytes.  Encrypt it in place on
        // the stack so the hot path avoids a metadata Vec and a separate
        // ciphertext Vec; the caller-owned frame itself is never copied.
        let mut metadata = [0u8; CIRCUIT_METADATA_LEN];
        metadata[..24].copy_from_slice(&frame[..24]);
        metadata[24..].copy_from_slice(&frame[frame.len() - TAG_LEN..]);
        let mut out = Vec::with_capacity(FORWARD_HEADER_LEN + ciphertext.len() + TAG_LEN);
        out.push(FORM_FORWARD);
        out.extend_from_slice(&sequence.to_be_bytes());
        let metadata_offset = out.len();
        out.resize(metadata_offset + CIRCUIT_METADATA_LEN, 0);
        out.extend_from_slice(ciphertext);
        let metadata_tag = self
            .send_cipher
            .encrypt_inout_detached(
                &Nonce::from(nonce(sequence)),
                &aad,
                InOutBuf::new(
                    &metadata,
                    &mut out[metadata_offset..metadata_offset + CIRCUIT_METADATA_LEN],
                )
                .map_err(|_| PhysicalError::Authentication)?,
            )
            .map_err(|_| PhysicalError::Authentication)?;
        out.extend_from_slice(&metadata_tag);
        Ok(out)
    }

    fn seal_fec_source(
        &self,
        transmission_sequence: u32,
        esi: u32,
        frame: &[u8],
    ) -> Result<Vec<u8>, PhysicalError> {
        if frame.len() < crypto::FRAME_OVERHEAD {
            return Err(PhysicalError::Truncated);
        }
        let sequence = self.next_sequence()?;
        let ciphertext = &frame[24..frame.len() - TAG_LEN];
        let mut prefix = [0u8; 8];
        prefix[..4].copy_from_slice(&transmission_sequence.to_be_bytes());
        prefix[4..].copy_from_slice(&esi.to_be_bytes());
        let aad = self.aad(
            FORM_FEC_SOURCE,
            sequence,
            ciphertext,
            self.direction,
            &prefix,
        );
        let mut metadata = [0u8; CIRCUIT_METADATA_LEN];
        metadata[..24].copy_from_slice(&frame[..24]);
        metadata[24..].copy_from_slice(&frame[frame.len() - TAG_LEN..]);
        let mut out = Vec::with_capacity(FORWARD_HEADER_LEN + ciphertext.len() + TAG_LEN + 8);
        out.push(FORM_FEC_SOURCE);
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&prefix);
        let metadata_offset = out.len();
        out.resize(metadata_offset + CIRCUIT_METADATA_LEN, 0);
        out.extend_from_slice(ciphertext);
        let metadata_tag = self
            .send_cipher
            .encrypt_inout_detached(
                &Nonce::from(nonce(sequence)),
                &aad,
                InOutBuf::new(
                    &metadata,
                    &mut out[metadata_offset..metadata_offset + CIRCUIT_METADATA_LEN],
                )
                .map_err(|_| PhysicalError::Authentication)?,
            )
            .map_err(|_| PhysicalError::Authentication)?;
        out.extend_from_slice(&metadata_tag);
        Ok(out)
    }

    pub fn seal(&self, payload: &PhysicalPayload) -> Result<Vec<u8>, PhysicalError> {
        if let PhysicalPayload::Forward(frame) = payload {
            return self.seal_forward(frame);
        }
        if let PhysicalPayload::FecSource {
            transmission_sequence,
            esi,
            frame,
        } = payload
        {
            return self.seal_fec_source(*transmission_sequence, *esi, frame);
        }
        let form = match payload {
            PhysicalPayload::Probe { .. } => FORM_PROBE,
            PhysicalPayload::ProbeAck { .. } => FORM_PROBE_ACK,
            PhysicalPayload::Keepalive => FORM_KEEPALIVE,
            PhysicalPayload::FecRepair { .. } => FORM_FEC_REPAIR,
            PhysicalPayload::Forward(_) | PhysicalPayload::FecSource { .. } => unreachable!(),
        };
        let sequence = self.next_sequence()?;
        let plaintext = encode_control(payload)?;
        let aad = self.aad(form, sequence, &[], self.direction, &[]);
        let ciphertext = self
            .send_cipher
            .encrypt(
                &Nonce::from(nonce(sequence)),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PhysicalError::Authentication)?;
        let mut out = vec![form];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
    pub fn open(&self, frame: &[u8]) -> Result<PhysicalPayload, PhysicalError> {
        if frame.len() < 1 + SEQUENCE_LEN + TAG_LEN {
            return Err(PhysicalError::Truncated);
        }
        let form = frame[0];
        if form > FORM_FEC_REPAIR {
            return Err(PhysicalError::Form(form));
        }
        let sequence = u64::from_be_bytes(frame[1..9].try_into().expect("sequence"));
        let payload = if form == FORM_FORWARD {
            if frame.len() < FORWARD_HEADER_LEN + TAG_LEN {
                return Err(PhysicalError::Truncated);
            }
            let metadata_ct = &frame[9..49];
            let ciphertext = &frame[49..frame.len() - TAG_LEN];
            let tag = &frame[frame.len() - TAG_LEN..];
            let aad = self.aad(form, sequence, ciphertext, self.receive_direction, &[]);
            let mut combined = [0u8; CIRCUIT_METADATA_LEN + TAG_LEN];
            combined[..CIRCUIT_METADATA_LEN].copy_from_slice(metadata_ct);
            combined[CIRCUIT_METADATA_LEN..].copy_from_slice(tag);
            let metadata = self
                .receive_cipher
                .decrypt(
                    &Nonce::from(nonce(sequence)),
                    Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| PhysicalError::Authentication)?;
            if metadata.len() != CIRCUIT_METADATA_LEN {
                return Err(PhysicalError::Encoding(
                    "invalid forward metadata length".into(),
                ));
            }
            let mut full = Vec::with_capacity(24 + ciphertext.len() + TAG_LEN);
            full.extend_from_slice(&metadata[..24]);
            full.extend_from_slice(ciphertext);
            full.extend_from_slice(&metadata[24..]);
            PhysicalPayload::Forward(full)
        } else if form == FORM_FEC_SOURCE {
            if frame.len() < FORWARD_HEADER_LEN + TAG_LEN + 8 {
                return Err(PhysicalError::Truncated);
            }
            let transmission_sequence =
                u32::from_be_bytes(frame[9..13].try_into().expect("transmission sequence"));
            let esi = u32::from_be_bytes(frame[13..17].try_into().expect("esi"));
            let metadata_ct = &frame[17..57];
            let ciphertext = &frame[57..frame.len() - TAG_LEN];
            let tag = &frame[frame.len() - TAG_LEN..];
            let mut prefix = [0u8; 8];
            prefix[..4].copy_from_slice(&transmission_sequence.to_be_bytes());
            prefix[4..].copy_from_slice(&esi.to_be_bytes());
            let aad = self.aad(form, sequence, ciphertext, self.receive_direction, &prefix);
            let mut combined = [0u8; CIRCUIT_METADATA_LEN + TAG_LEN];
            combined[..CIRCUIT_METADATA_LEN].copy_from_slice(metadata_ct);
            combined[CIRCUIT_METADATA_LEN..].copy_from_slice(tag);
            let metadata = self
                .receive_cipher
                .decrypt(
                    &Nonce::from(nonce(sequence)),
                    Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| PhysicalError::Authentication)?;
            if metadata.len() != CIRCUIT_METADATA_LEN {
                return Err(PhysicalError::Encoding(
                    "invalid FEC source metadata length".into(),
                ));
            }
            let mut full = Vec::with_capacity(24 + ciphertext.len() + TAG_LEN);
            full.extend_from_slice(&metadata[..24]);
            full.extend_from_slice(ciphertext);
            full.extend_from_slice(&metadata[24..]);
            PhysicalPayload::FecSource {
                transmission_sequence,
                esi,
                frame: full,
            }
        } else {
            let body = &frame[9..];
            let aad = self.aad(form, sequence, &[], self.receive_direction, &[]);
            let plain = self
                .receive_cipher
                .decrypt(
                    &Nonce::from(nonce(sequence)),
                    Payload {
                        msg: body,
                        aad: &aad,
                    },
                )
                .map_err(|_| PhysicalError::Authentication)?;
            decode_control(form, plain)?
        };
        if !self
            .replay
            .lock()
            .expect("physical replay lock")
            .accept(sequence)
        {
            return Err(PhysicalError::Replay);
        }
        Ok(payload)
    }
    fn aad(
        &self,
        form: u8,
        sequence: u64,
        ciphertext: &[u8],
        direction: u8,
        extra: &[u8],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + 8 + extra.len() + ciphertext.len() + 16 + 16 + 32 + 1);
        aad.push(form);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.extend_from_slice(extra);
        aad.extend_from_slice(ciphertext);
        if direction == self.direction {
            aad.extend_from_slice(&self.local_id);
            aad.extend_from_slice(&self.peer_id);
        } else {
            aad.extend_from_slice(&self.peer_id);
            aad.extend_from_slice(&self.local_id);
        }
        aad.extend_from_slice(&self.link_nonce);
        aad.push(direction);
        aad
    }
}

fn nonce(sequence: u64) -> [u8; 12] {
    let mut out = [0; 12];
    out[4..].copy_from_slice(&sequence.to_be_bytes());
    out
}
fn encode_control(payload: &PhysicalPayload) -> Result<Vec<u8>, PhysicalError> {
    let mut out = crate::wire::Writer::new();
    match payload {
        PhysicalPayload::Probe {
            probe_id,
            target_len,
            padding,
        } => {
            out.u64(*probe_id);
            out.u16(*target_len);
            out.bytes(padding);
        }
        PhysicalPayload::ProbeAck {
            probe_id,
            target_len,
        } => {
            out.u64(*probe_id);
            out.u16(*target_len);
        }
        PhysicalPayload::Keepalive => {}
        PhysicalPayload::FecRepair {
            transmission_sequence,
            rid,
            first_esi,
            symbol_count,
            vector,
        } => {
            if *symbol_count == 0 || usize::from(*symbol_count) > crate::fec::MAX_REPAIR_WINDOW {
                return Err(PhysicalError::Encoding("invalid FEC repair count".into()));
            }
            if vector.is_empty() || vector.len() > crate::fec::MAX_SYMBOL_BYTES {
                return Err(PhysicalError::Encoding("invalid FEC repair vector".into()));
            }
            out.u32(*transmission_sequence);
            out.u32(*rid);
            out.u32(*first_esi);
            out.u16(*symbol_count);
            out.bytes(vector);
        }
        PhysicalPayload::FecSource { .. } => {
            return Err(PhysicalError::Encoding(
                "FEC source is not a control payload".into(),
            ));
        }
        PhysicalPayload::Forward(_) => {
            return Err(PhysicalError::Encoding(
                "forward is not a control payload".into(),
            ));
        }
    }
    Ok(out.finish())
}
fn decode_control(form: u8, bytes: Vec<u8>) -> Result<PhysicalPayload, PhysicalError> {
    let mut input = crate::wire::Reader::new(&bytes);
    let result = match form {
        FORM_TOPOLOGY => return Err(PhysicalError::Form(FORM_TOPOLOGY)),
        FORM_PROBE => PhysicalPayload::Probe {
            probe_id: input
                .u64()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?,
            target_len: input
                .u16()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?,
            padding: {
                // Bound the transient allocation before copying; the carrier
                // already bounds control frames, this keeps future
                // control-stream framing from amplifying an unbounded copy.
                if input.remaining().len() > MAX_PROBE_PADDING_BYTES {
                    return Err(PhysicalError::Encoding(
                        "probe padding exceeds limit".into(),
                    ));
                }
                input.take_remaining().to_vec()
            },
        },
        FORM_PROBE_ACK => PhysicalPayload::ProbeAck {
            probe_id: input
                .u64()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?,
            target_len: input
                .u16()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?,
        },
        FORM_KEEPALIVE => PhysicalPayload::Keepalive,
        FORM_FEC_REPAIR => {
            let transmission_sequence = input
                .u32()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?;
            let rid = input
                .u32()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?;
            let first_esi = input
                .u32()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?;
            let symbol_count = input
                .u16()
                .map_err(|e| PhysicalError::Encoding(e.to_string()))?;
            if symbol_count == 0 || usize::from(symbol_count) > crate::fec::MAX_REPAIR_WINDOW {
                return Err(PhysicalError::Encoding("invalid FEC repair count".into()));
            }
            let remaining = input.remaining().len();
            if remaining == 0 || remaining > crate::fec::MAX_SYMBOL_BYTES {
                return Err(PhysicalError::Encoding("invalid FEC repair vector".into()));
            }
            let vector = input.take_remaining().to_vec();
            PhysicalPayload::FecRepair {
                transmission_sequence,
                rid,
                first_esi,
                symbol_count,
                vector,
            }
        }
        FORM_FEC_SOURCE => {
            return Err(PhysicalError::Encoding(
                "FEC source uses forward framing".into(),
            ));
        }
        _ => return Err(PhysicalError::Form(form)),
    };
    input
        .finish()
        .map_err(|e| PhysicalError::Encoding(e.to_string()))?;
    Ok(result)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate;
    #[test]
    fn control_decode_rejects_oversized_probe_and_repair_vectors() {
        use crate::wire::Writer;
        let mut probe = Writer::new();
        probe.u64(1);
        probe.u16(64);
        probe.bytes(&vec![0u8; MAX_PROBE_PADDING_BYTES + 1]);
        assert!(decode_control(FORM_PROBE, probe.finish()).is_err());

        let mut repair = Writer::new();
        repair.u32(1);
        repair.u32(2);
        repair.u32(3);
        repair.u16(1);
        repair.bytes(&vec![0u8; crate::fec::MAX_SYMBOL_BYTES + 1]);
        assert!(decode_control(FORM_FEC_REPAIR, repair.finish()).is_err());
    }

    #[test]
    fn forward_keeps_circuit_ciphertext_opaque_but_reconstructs_frame() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[7; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[7; 32]).unwrap();
        let mut frame = vec![1; 24];
        frame.extend_from_slice(&[2; 80]);
        frame.extend_from_slice(&[3; 16]);
        let wire = ab.seal(&PhysicalPayload::Forward(frame.clone())).unwrap();
        assert_eq!(wire[0], FORM_FORWARD);
        assert_eq!(&wire[49..wire.len() - 16], &[2; 80]);
        assert_eq!(ba.open(&wire).unwrap(), PhysicalPayload::Forward(frame));
    }

    #[test]
    fn borrowed_forward_sealing_round_trips() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[9; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[9; 32]).unwrap();
        let mut frame = vec![0; crypto::FRAME_OVERHEAD + 32];
        frame[..16].copy_from_slice(&[7; 16]);

        let wire = ab.seal_forward(&frame).unwrap();
        assert_eq!(ba.open(&wire).unwrap(), PhysicalPayload::Forward(frame));
    }

    #[test]
    fn fec_source_and_repair_round_trip_with_authenticated_metadata() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[6; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[6; 32]).unwrap();
        let mut frame = vec![1; 24];
        frame.extend_from_slice(&[2; 80]);
        frame.extend_from_slice(&[3; 16]);
        let source = PhysicalPayload::FecSource {
            transmission_sequence: 9,
            esi: 4,
            frame: frame.clone(),
        };
        let wire = ab.seal(&source).unwrap();
        assert_eq!(wire.len(), source.wire_len().unwrap());
        assert_eq!(ba.open(&wire).unwrap(), source);

        let repair = PhysicalPayload::FecRepair {
            transmission_sequence: 10,
            rid: 5,
            first_esi: 2,
            symbol_count: 3,
            vector: vec![7; frame.len() + 2],
        };
        let wire = ab.seal(&repair).unwrap();
        assert_eq!(wire.len(), repair.wire_len().unwrap());
        assert_eq!(ba.open(&wire).unwrap(), repair);
    }

    #[test]
    fn fec_repair_wire_len_rejects_unencodable_vectors() {
        let repair = PhysicalPayload::FecRepair {
            transmission_sequence: 10,
            rid: 5,
            first_esi: 2,
            symbol_count: 3,
            vector: vec![7; crate::fec::MAX_SYMBOL_BYTES + 1],
        };
        assert_eq!(
            repair.wire_len(),
            Err(PhysicalError::Encoding("invalid FEC repair vector".into()))
        );
    }

    #[test]
    fn fec_source_prefix_tampering_is_authenticated() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[5; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[5; 32]).unwrap();
        let frame = vec![0; crypto::FRAME_OVERHEAD + 8];
        let mut wire = ab
            .seal(&PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 2,
                frame,
            })
            .unwrap();
        wire[9] ^= 1;
        assert_eq!(ba.open(&wire), Err(PhysicalError::Authentication));
    }
    #[test]
    fn tamper_and_replay_are_rejected() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[8; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[8; 32]).unwrap();
        let mut frame = vec![1; 24];
        frame.extend_from_slice(&[2; 8]);
        frame.extend_from_slice(&[3; 16]);
        let mut wire = ab.seal(&PhysicalPayload::Forward(frame)).unwrap();
        wire[49] ^= 1;
        assert_eq!(ba.open(&wire), Err(PhysicalError::Authentication));
        let wire = ab
            .seal(&PhysicalPayload::ProbeAck {
                probe_id: 1,
                target_len: 1200,
            })
            .unwrap();
        assert!(ba.open(&wire).is_ok());
        assert_eq!(ba.open(&wire), Err(PhysicalError::Replay));
    }
    #[test]
    fn topology_form_is_reserved() {
        let a = generate();
        let b = generate();
        let ab = PhysicalSession::new(&a, &b.verifying_key(), &[9; 32]).unwrap();
        let ba = PhysicalSession::new(&b, &a.verifying_key(), &[9; 32]).unwrap();
        let p = ab
            .seal(&PhysicalPayload::ProbeAck {
                probe_id: 1,
                target_len: 1200,
            })
            .unwrap();
        assert_eq!(u64::from_be_bytes(p[1..9].try_into().unwrap()), 0);
        assert!(ba.open(&p).is_ok());
        let keepalive = ab.seal(&PhysicalPayload::Keepalive).unwrap();
        assert_eq!(ba.open(&keepalive), Ok(PhysicalPayload::Keepalive));
        let probe = ab
            .seal(&PhysicalPayload::Probe {
                probe_id: 2,
                target_len: 1200,
                padding: vec![0xaa; 37],
            })
            .unwrap();
        assert_eq!(
            ba.open(&probe),
            Ok(PhysicalPayload::Probe {
                probe_id: 2,
                target_len: 1200,
                padding: vec![0xaa; 37],
            })
        );
    }

    #[test]
    fn bare_probe_capacity_counts_receive_id_exactly_once() {
        let probe = PhysicalPayload::Probe {
            probe_id: 1,
            target_len: 1200,
            padding: vec![0; 1200 - 39],
        };
        assert_eq!(probe.wire_len().unwrap(), 1196);
        assert_eq!(probe.wire_len().unwrap() + 4, 1200);
        assert_eq!(
            PhysicalPayload::ProbeAck {
                probe_id: 1,
                target_len: 1200
            }
            .wire_len()
            .unwrap(),
            35
        );
    }

    #[test]
    fn forward_capacity_matches_user_ip_plus_tinect_overhead() {
        let user_ip_len = 1130;
        let frame = vec![0; crypto::FRAME_OVERHEAD + user_ip_len];
        let physical_len = PhysicalPayload::Forward(frame).wire_len().unwrap();
        assert_eq!(physical_len, 1196);
        assert_eq!(physical_len + crate::mtu::BARE_RECEIVE_ID_LEN, 1200);

        let user_ip_len = 1134;
        let frame = vec![0; crypto::FRAME_OVERHEAD + user_ip_len];
        assert_eq!(
            PhysicalPayload::Forward(frame).wire_len().unwrap(),
            crate::mtu::INITIAL_QUIC_PATH_PAYLOAD_SIZE
        );
    }

    #[test]
    fn physical_session_rejects_invalid_lengths_forms_and_control_payloads() {
        let a = generate();
        let b = generate();
        assert!(matches!(
            PhysicalSession::new(&a, &b.verifying_key(), &[0; 31]),
            Err(PhysicalError::Encoding(_))
        ));
        let session = PhysicalSession::new(&a, &b.verifying_key(), &[10; 32]).unwrap();
        assert_eq!(
            session.seal_forward(&[0; crypto::FRAME_OVERHEAD - 1]),
            Err(PhysicalError::Truncated)
        );
        assert_eq!(
            session.seal(&PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 1,
                frame: vec![0; crypto::FRAME_OVERHEAD - 1],
            }),
            Err(PhysicalError::Truncated)
        );
        assert!(matches!(
            session.seal(&PhysicalPayload::FecRepair {
                transmission_sequence: 1,
                rid: 1,
                first_esi: 1,
                symbol_count: 0,
                vector: vec![1],
            }),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            session.seal(&PhysicalPayload::FecRepair {
                transmission_sequence: 1,
                rid: 1,
                first_esi: 1,
                symbol_count: 1,
                vector: Vec::new(),
            }),
            Err(PhysicalError::Encoding(_))
        ));
        session.send_sequence.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(
            session.seal(&PhysicalPayload::Keepalive),
            Err(PhysicalError::Sequence)
        );

        assert_eq!(session.open(&[]), Err(PhysicalError::Truncated));
        assert_eq!(session.open(&[0xff; 25]), Err(PhysicalError::Form(0xff)));
        assert_eq!(
            session.open(&[FORM_FORWARD; FORWARD_HEADER_LEN + TAG_LEN - 1]),
            Err(PhysicalError::Truncated)
        );
        assert_eq!(
            session.open(&[FORM_FEC_SOURCE; FORWARD_HEADER_LEN + TAG_LEN + 8 - 1]),
            Err(PhysicalError::Truncated)
        );

        assert!(matches!(
            encode_control(&PhysicalPayload::Forward(Vec::new())),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            encode_control(&PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 1,
                frame: Vec::new(),
            }),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            decode_control(FORM_TOPOLOGY, Vec::new()),
            Err(PhysicalError::Form(FORM_TOPOLOGY))
        ));
        assert!(matches!(
            decode_control(FORM_FEC_SOURCE, Vec::new()),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            decode_control(FORM_PROBE, Vec::new()),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            decode_control(FORM_PROBE_ACK, Vec::new()),
            Err(PhysicalError::Encoding(_))
        ));
        assert!(matches!(
            decode_control(FORM_FEC_REPAIR, vec![0; 14]),
            Err(PhysicalError::Encoding(_))
        ));
        let mut invalid_count = Vec::new();
        invalid_count.extend_from_slice(&1_u32.to_be_bytes());
        invalid_count.extend_from_slice(&2_u32.to_be_bytes());
        invalid_count.extend_from_slice(&3_u32.to_be_bytes());
        invalid_count.extend_from_slice(&0_u16.to_be_bytes());
        invalid_count.push(1);
        assert!(matches!(
            decode_control(FORM_FEC_REPAIR, invalid_count),
            Err(PhysicalError::Encoding(message)) if message.contains("repair count")
        ));
        let mut empty_vector = Vec::new();
        empty_vector.extend_from_slice(&1_u32.to_be_bytes());
        empty_vector.extend_from_slice(&2_u32.to_be_bytes());
        empty_vector.extend_from_slice(&3_u32.to_be_bytes());
        empty_vector.extend_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            decode_control(FORM_FEC_REPAIR, empty_vector),
            Err(PhysicalError::Encoding(message)) if message.contains("repair vector")
        ));
        let mut valid_repair = Vec::new();
        valid_repair.extend_from_slice(&1_u32.to_be_bytes());
        valid_repair.extend_from_slice(&2_u32.to_be_bytes());
        valid_repair.extend_from_slice(&3_u32.to_be_bytes());
        valid_repair.extend_from_slice(&1_u16.to_be_bytes());
        valid_repair.push(9);
        assert!(matches!(
            decode_control(FORM_FEC_REPAIR, valid_repair),
            Ok(PhysicalPayload::FecRepair { vector, .. }) if vector == vec![9]
        ));
        assert!(matches!(
            decode_control(FORM_KEEPALIVE, vec![0]),
            Err(PhysicalError::Encoding(_))
        ));
    }

    #[test]
    fn physical_control_forms_and_wire_lengths_cover_valid_and_invalid_shapes() {
        let forward = PhysicalPayload::Forward(vec![0; crypto::FRAME_OVERHEAD]);
        assert_eq!(
            forward.wire_len().unwrap(),
            FORWARD_OVERHEAD + crypto::FRAME_OVERHEAD
        );
        assert_eq!(
            PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 2,
                frame: vec![0; crypto::FRAME_OVERHEAD],
            }
            .wire_len()
            .unwrap(),
            FORWARD_OVERHEAD + crypto::FRAME_OVERHEAD + 8
        );
        assert!(
            PhysicalPayload::Probe {
                probe_id: 1,
                target_len: 64,
                padding: vec![0; 3],
            }
            .wire_len()
            .is_ok()
        );
        assert!(
            PhysicalPayload::ProbeAck {
                probe_id: 1,
                target_len: 64,
            }
            .wire_len()
            .is_ok()
        );
        assert!(PhysicalPayload::Keepalive.wire_len().is_ok());

        let controls = [
            PhysicalPayload::Probe {
                probe_id: 7,
                target_len: 64,
                padding: vec![1, 2, 3],
            },
            PhysicalPayload::ProbeAck {
                probe_id: 8,
                target_len: 65,
            },
            PhysicalPayload::Keepalive,
            PhysicalPayload::FecRepair {
                transmission_sequence: 9,
                rid: 10,
                first_esi: 11,
                symbol_count: 1,
                vector: vec![12],
            },
        ];
        for payload in controls {
            let (form, expected) = match &payload {
                PhysicalPayload::Probe { .. } => (FORM_PROBE, payload.clone()),
                PhysicalPayload::ProbeAck { .. } => (FORM_PROBE_ACK, payload.clone()),
                PhysicalPayload::Keepalive => (FORM_KEEPALIVE, payload.clone()),
                PhysicalPayload::FecRepair { .. } => (FORM_FEC_REPAIR, payload.clone()),
                _ => unreachable!(),
            };
            let encoded = encode_control(&payload).unwrap();
            assert_eq!(decode_control(form, encoded).unwrap(), expected);
        }
        assert!(matches!(
            PhysicalPayload::FecRepair {
                transmission_sequence: 1,
                rid: 1,
                first_esi: 1,
                symbol_count: 0,
                vector: vec![1],
            }
            .wire_len(),
            Err(PhysicalError::Encoding(_))
        ));
    }
}
