//! End-to-end DATA protection. Circuit keys are established by signed OPEN.
use crate::circuit::CircuitId;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadInOut, KeyInit, Payload},
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use inout::InOutBuf;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const DOMAIN: &[u8] = b"tinect-payload-v3\0";
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 16 + 8 + 1;
pub const FRAME_OVERHEAD: usize = HEADER_LEN + TAG_LEN;
const REPLAY_WINDOW_BITS: usize = 65_536;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid source public key")]
    InvalidPublicKey,
    #[error("encrypted frame is truncated")]
    Truncated,
    #[error("no session exists for circuit")]
    UnknownSession,
    #[error("payload authentication failed")]
    Authentication,
    #[error("replayed frame")]
    Replay,
    #[error("session sequence exhausted")]
    Sequence,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum DataDirection {
    Forward,
    Return,
    DnsForward,
    DnsReturn,
}

impl DataDirection {
    fn byte(self) -> u8 {
        match self {
            Self::Forward => 0,
            Self::Return => 1,
            Self::DnsForward => 2,
            Self::DnsReturn => 3,
        }
    }

    fn parse(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            0 => Ok(Self::Forward),
            1 => Ok(Self::Return),
            2 => Ok(Self::DnsForward),
            3 => Ok(Self::DnsReturn),
            _ => Err(CryptoError::Authentication),
        }
    }
}

fn directional_key(key: &Key, direction: DataDirection) -> Key {
    let hkdf = Hkdf::<Sha256>::new(Some(b"tinect-data-direction-v1"), key.as_slice());
    let mut output = [0_u8; 32];
    hkdf.expand(&[direction.byte()], &mut output)
        .expect("SHA-256 HKDF accepts a 32-byte output");
    Key::from(output)
}

pub(crate) fn private_x25519(identity: &ed25519_dalek::SigningKey) -> StaticSecret {
    let digest = Sha512::digest(identity.to_bytes());
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest[..32]);
    StaticSecret::from(bytes)
}
pub fn public_x25519(identity: &VerifyingKey) -> Result<PublicKey, CryptoError> {
    let point = CompressedEdwardsY::from_slice(identity.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?
        .decompress()
        .ok_or(CryptoError::InvalidPublicKey)?;
    Ok(PublicKey::from(point.to_montgomery().to_bytes()))
}
pub fn derive_key(
    shared: &[u8; 32],
    source: &VerifyingKey,
    destination: &VerifyingKey,
    circuit_id: CircuitId,
    ephemeral: &[u8; 32],
) -> Key {
    let hkdf = Hkdf::<Sha256>::new(Some(DOMAIN), shared);
    let mut info = Vec::with_capacity(32 + 32 + 16 + 32);
    info.extend_from_slice(source.as_bytes());
    info.extend_from_slice(destination.as_bytes());
    info.extend_from_slice(&circuit_id.0);
    info.extend_from_slice(ephemeral);
    let mut out = [0; 32];
    hkdf.expand(&info, &mut out).expect("key length");
    Key::from(out)
}
fn nonce(sequence: u64) -> [u8; 12] {
    let mut out = [0; 12];
    out[4..].copy_from_slice(&sequence.to_be_bytes());
    out
}

#[derive(Clone)]
pub struct Session {
    source: VerifyingKey,
    cipher: ChaCha20Poly1305,
    replay: ReplayWindow,
}
#[derive(Clone)]
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    bits: Box<[u64; REPLAY_WINDOW_WORDS]>,
}
impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bits: Box::new([0; REPLAY_WINDOW_WORDS]),
        }
    }
}
impl ReplayWindow {
    pub(crate) fn contains(&self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            return false;
        };
        if sequence > highest {
            return false;
        }
        let distance = usize::try_from(highest - sequence).unwrap_or(usize::MAX);
        if distance >= REPLAY_WINDOW_BITS {
            return true;
        }
        let word = distance / 64;
        let bit = distance % 64;
        self.bits[word] & (1u64 << bit) != 0
    }

    pub(crate) fn accept(&mut self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bits[0] = 1;
            return true;
        };
        if sequence > highest {
            let shift = usize::try_from(sequence - highest).unwrap_or(usize::MAX);
            if shift >= REPLAY_WINDOW_BITS {
                self.bits.fill(0);
            } else {
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for index in (0..REPLAY_WINDOW_WORDS).rev() {
                    self.bits[index] = if index >= word_shift {
                        let source = index - word_shift;
                        (self.bits[source] << bit_shift)
                            | if bit_shift > 0 && source > 0 {
                                self.bits[source - 1] >> (64 - bit_shift)
                            } else {
                                0
                            }
                    } else {
                        0
                    };
                }
            }
            self.bits[0] |= 1;
            self.highest = Some(sequence);
            return true;
        }
        let distance = usize::try_from(highest - sequence).unwrap_or(usize::MAX);
        if distance >= REPLAY_WINDOW_BITS {
            return false;
        }
        let word = distance / 64;
        let bit = distance % 64;
        let mask = 1u64 << bit;
        if self.bits[word] & mask != 0 {
            return false;
        }
        self.bits[word] |= mask;
        true
    }
}

pub struct SenderSession {
    circuit_id: CircuitId,
    cipher: ChaCha20Poly1305,
    sequence: u64,
    exhausted: bool,
    direction: DataDirection,
    /// Reused frame buffer: the ciphertext is produced in place after the
    /// header, so the steady state encrypts with zero heap allocations.
    buffer: Vec<u8>,
}
impl SenderSession {
    pub fn from_key(circuit_id: CircuitId, key: Key) -> Self {
        Self::from_key_with_direction(circuit_id, key, DataDirection::Forward)
    }

    pub fn return_from_key(circuit_id: CircuitId, key: Key) -> Self {
        Self::from_key_with_direction(circuit_id, key, DataDirection::Return)
    }

    pub fn dns_from_key(circuit_id: CircuitId, key: Key) -> Self {
        Self::from_key_with_direction(circuit_id, key, DataDirection::DnsForward)
    }

    pub fn dns_return_from_key(circuit_id: CircuitId, key: Key) -> Self {
        Self::from_key_with_direction(circuit_id, key, DataDirection::DnsReturn)
    }

    fn from_key_with_direction(circuit_id: CircuitId, key: Key, direction: DataDirection) -> Self {
        Self {
            circuit_id,
            cipher: ChaCha20Poly1305::new(&directional_key(&key, direction)),
            sequence: 0,
            exhausted: false,
            direction,
            buffer: Vec::new(),
        }
    }
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<&[u8], CryptoError> {
        if self.exhausted {
            return Err(CryptoError::Sequence);
        }
        let sequence = self.sequence;
        if sequence == u64::MAX {
            self.exhausted = true;
        } else {
            self.sequence += 1;
        }
        self.buffer.clear();
        self.buffer.reserve(HEADER_LEN + packet.len() + TAG_LEN);
        self.buffer.extend_from_slice(&self.circuit_id.0);
        self.buffer.extend_from_slice(&sequence.to_be_bytes());
        self.buffer.push(self.direction.byte());
        let header_len = self.buffer.len();
        self.buffer.resize(header_len + packet.len(), 0);
        let (header, ciphertext_out) = self.buffer.split_at_mut(header_len);
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &Nonce::from(nonce(sequence)),
                header,
                InOutBuf::new(packet, ciphertext_out).map_err(|_| CryptoError::Authentication)?,
            )
            .map_err(|_| CryptoError::Authentication)?;
        self.buffer.extend_from_slice(&tag);
        Ok(&self.buffer)
    }
}

#[derive(Default)]
pub struct ReceiverSessions {
    current: HashMap<(CircuitId, DataDirection), Session>,
}
impl ReceiverSessions {
    pub fn install(&mut self, circuit_id: CircuitId, source: VerifyingKey, key: Key) {
        self.install_direction(circuit_id, source, key, DataDirection::Forward);
        self.install_direction(circuit_id, source, key, DataDirection::DnsForward);
    }

    pub fn install_return(&mut self, circuit_id: CircuitId, source: VerifyingKey, key: Key) {
        self.install_direction(circuit_id, source, key, DataDirection::Return);
        self.install_direction(circuit_id, source, key, DataDirection::DnsReturn);
    }

    fn install_direction(
        &mut self,
        circuit_id: CircuitId,
        source: VerifyingKey,
        key: Key,
        direction: DataDirection,
    ) {
        match self.current.entry((circuit_id, direction)) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Session {
                    source,
                    cipher: ChaCha20Poly1305::new(&directional_key(&key, direction)),
                    replay: ReplayWindow::default(),
                });
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                // `circuit.rs` rejects rebinding the same CircuitId to
                // different OPEN fields, so a duplicate install must carry the
                // same source. Keep the original session (and its replay
                // window) and surface a mismatch instead of silently rotating
                // keys under an active circuit. Only a `warn` (no metric):
                // this layer has no observability handle, and the warn is
                // sufficient to spot a stuck pre-rotation key.
                if entry.get().source != source {
                    tracing::warn!(
                        ?circuit_id,
                        ?direction,
                        "duplicate circuit session install with mismatched source keeps the original session"
                    );
                }
            }
        }
    }
    pub fn remove(&mut self, circuit_id: CircuitId) {
        self.current.retain(|(id, _), _| *id != circuit_id);
    }
    pub fn open_data(
        &mut self,
        frame: &[u8],
    ) -> Result<(CircuitId, DataDirection, VerifyingKey, Vec<u8>), CryptoError> {
        if frame.len() < FRAME_OVERHEAD {
            return Err(CryptoError::Truncated);
        }
        let circuit_id = CircuitId(frame[..16].try_into().expect("id"));
        let sequence = u64::from_be_bytes(frame[16..24].try_into().expect("sequence"));
        let direction = DataDirection::parse(frame[24])?;
        let session = self
            .current
            .get(&(circuit_id, direction))
            .ok_or(CryptoError::UnknownSession)?;
        // Cheap pre-check before the AEAD: a replayed copy of a valid frame
        // must not force a full ChaCha20Poly1305 decryption per copy.
        if session.replay.contains(sequence) {
            return Err(CryptoError::Replay);
        }
        let session = self
            .current
            .get_mut(&(circuit_id, direction))
            .ok_or(CryptoError::UnknownSession)?;
        let packet = session
            .cipher
            .decrypt(
                &Nonce::from(nonce(sequence)),
                Payload {
                    msg: &frame[HEADER_LEN..],
                    aad: &frame[..HEADER_LEN],
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        if !session.replay.accept(sequence) {
            return Err(CryptoError::Replay);
        }
        Ok((circuit_id, direction, session.source, packet))
    }
}
pub fn frame_circuit_id(frame: &[u8]) -> Result<CircuitId, CryptoError> {
    frame
        .get(..16)
        .ok_or(CryptoError::Truncated)?
        .try_into()
        .map(CircuitId)
        .map_err(|_| CryptoError::Truncated)
}
pub fn open_key(
    identity: &ed25519_dalek::SigningKey,
    source: &VerifyingKey,
    circuit_id: CircuitId,
    ephemeral: [u8; 32],
) -> Result<Key, CryptoError> {
    let shared = private_x25519(identity).diffie_hellman(&PublicKey::from(ephemeral));
    Ok(derive_key(
        shared.as_bytes(),
        source,
        &identity.verifying_key(),
        circuit_id,
        &ephemeral,
    ))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::Key;

    #[test]
    fn data_is_isolated_by_random_circuit_id_and_last_sequence_is_not_reused() {
        let source = crate::identity::generate();
        let id = CircuitId([7; 16]);
        let key = Key::from([3; 32]);
        let mut sender = SenderSession::from_key(id, key);
        sender.sequence = u64::MAX;
        let frame = sender.encrypt(b"packet").unwrap().to_vec();
        assert_eq!(
            u64::from_be_bytes(frame[16..24].try_into().unwrap()),
            u64::MAX
        );
        assert_eq!(sender.encrypt(b"second"), Err(CryptoError::Sequence));
        let mut receiver = ReceiverSessions::default();
        receiver.install(id, source.verifying_key(), key);
        assert_eq!(receiver.open_data(&frame).unwrap().3, b"packet");
        assert_eq!(receiver.open_data(&frame), Err(CryptoError::Replay));
    }

    #[test]
    fn forward_and_return_use_distinct_authenticated_directions() {
        let source = crate::identity::generate();
        let id = CircuitId([9; 16]);
        let key = Key::from([5; 32]);
        let mut sender = SenderSession::return_from_key(id, key);
        let frame = sender.encrypt(b"reply").unwrap().to_vec();
        let mut receiver = ReceiverSessions::default();
        receiver.install_return(id, source.verifying_key(), key);
        let (_, direction, _, packet) = receiver.open_data(&frame).unwrap();
        assert_eq!(direction, DataDirection::Return);
        assert_eq!(packet, b"reply");
    }

    #[test]
    fn replay_window_allows_authenticated_reordering_but_not_duplicates_or_old_frames() {
        let mut window = ReplayWindow::default();
        assert!(!window.contains(100));
        assert!(window.accept(100));
        assert!(window.contains(100));
        assert!(!window.contains(101));
        assert!(window.accept(102));
        assert!(window.accept(101));
        assert!(!window.accept(101));
        assert!(window.contains(101));
        assert!(window.accept(102 + 65_535));
        assert!(!window.accept(102));
        assert!(window.accept(1_000_000));
        assert!(!window.accept(100));
    }

    #[test]
    fn duplicate_install_with_mismatched_source_keeps_original_session() {
        let first = crate::identity::generate();
        let second = crate::identity::generate();
        let id = CircuitId([11; 16]);
        let key = Key::from([7; 32]);
        let mut sender = SenderSession::from_key(id, key);
        let frame = sender.encrypt(b"packet").unwrap().to_vec();
        let mut receiver = ReceiverSessions::default();
        receiver.install(id, first.verifying_key(), key);
        receiver.install(id, second.verifying_key(), key);
        let (_, _, source, packet) = receiver.open_data(&frame).unwrap();
        assert_eq!(source, first.verifying_key());
        assert_eq!(packet, b"packet");
    }
}
