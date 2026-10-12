use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid Ed25519 key: {0}")]
    InvalidKey(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn generate() -> SigningKey {
    SigningKey::generate(&mut UnwrapErr(SysRng))
}
pub fn encode_secret(key: &SigningKey) -> String {
    STANDARD_NO_PAD.encode(key.to_bytes())
}
pub fn decode_secret(s: &str) -> Result<SigningKey, IdentityError> {
    let bytes = STANDARD_NO_PAD
        .decode(s.trim())
        .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("secret must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&raw))
}
pub fn encode_public(key: &VerifyingKey) -> String {
    STANDARD_NO_PAD.encode(key.to_bytes())
}
pub fn decode_public(s: &str) -> Result<VerifyingKey, IdentityError> {
    let bytes = STANDARD_NO_PAD
        .decode(s.trim())
        .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&raw).map_err(|e| IdentityError::InvalidKey(e.to_string()))
}
pub fn node_id(key: &VerifyingKey) -> String {
    let hash = Sha256::digest(key.as_bytes());
    hex(&hash[..16])
}

/// Binary wire representation of a node identity.
pub fn node_id_bytes(key: &VerifyingKey) -> [u8; 16] {
    Sha256::digest(key.as_bytes())[..16]
        .try_into()
        .expect("SHA-256 prefix has sixteen bytes")
}
pub fn load_secret(path: impl AsRef<Path>) -> Result<SigningKey, IdentityError> {
    decode_secret(&fs::read_to_string(path)?)
}
pub fn save_secret(path: impl AsRef<Path>, key: &SigningKey) -> Result<(), IdentityError> {
    let path = path.as_ref();
    fs::write(path, format!("{}\n", encode_secret(key)))?;
    // A private key must never inherit a permissive umask.  Restrict it to
    // the owner even if the file was just created.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let k = generate();
        assert_eq!(
            decode_secret(&encode_secret(&k)).unwrap().verifying_key(),
            k.verifying_key()
        );
        assert_eq!(node_id(&k.verifying_key()).len(), 32);
        assert_eq!(node_id_bytes(&k.verifying_key()).len(), 16);
    }

    #[cfg(unix)]
    #[test]
    fn saved_secret_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret");
        save_secret(&path, &generate()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
