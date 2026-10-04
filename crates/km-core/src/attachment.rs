//! Encrypted file attachments.
//!
//! A file is sealed on the sender's device with a fresh random key
//! (XChaCha20-Poly1305, random nonce in front), and only the ciphertext goes
//! to the server. The key, the ciphertext's SHA-256 and the download token
//! travel inside the end-to-end encrypted message (`km_proto::Attachment`),
//! so the server can neither read the file nor swap it for another.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// The largest file (plaintext) anyone may send.
pub const MAX_ATTACHMENT: usize = 25 * 1024 * 1024;
const NONCE: usize = 24;

/// A sealed file: what to upload, and what the message carries.
pub struct SealedAttachment {
    pub ciphertext: Vec<u8>,
    pub key: Zeroizing<[u8; 32]>,
    pub sha256: [u8; 32],
}

pub fn seal_attachment(plaintext: &[u8]) -> Result<SealedAttachment> {
    if plaintext.len() > MAX_ATTACHMENT {
        return Err(CoreError::TooLarge);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| CoreError::State)?;
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut nonce).map_err(|_| CoreError::State)?;
    let sealed = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CoreError::BadKey)?
        .encrypt(&XNonce::from(nonce), plaintext)
        .map_err(|_| CoreError::State)?;
    let mut ciphertext = Vec::with_capacity(NONCE + sealed.len());
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&sealed);
    let sha256 = Sha256::digest(&ciphertext).into();
    Ok(SealedAttachment { ciphertext, key, sha256 })
}

/// Check the downloaded ciphertext against the hash in the message, then open
/// it. A swapped or damaged file fails before decryption is even tried.
pub fn open_attachment(key: &[u8], sha256: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || sha256.len() != 32 || ciphertext.len() < NONCE + 16 {
        return Err(CoreError::Malformed);
    }
    let actual: [u8; 32] = Sha256::digest(ciphertext).into();
    if actual.as_slice() != sha256 {
        return Err(CoreError::Undecryptable);
    }
    let nonce: [u8; NONCE] = ciphertext[..NONCE].try_into().map_err(|_| CoreError::Malformed)?;
    let plain = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::BadKey)?
        .decrypt(&XNonce::from(nonce), &ciphertext[NONCE..])
        .map_err(|_| CoreError::Undecryptable)?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_a_swapped_file_is_refused() {
        let file = b"a small screenshot, pretend".repeat(100);
        let sealed = seal_attachment(&file).unwrap();
        assert!(!sealed.ciphertext.windows(20).any(|w| w == &file[..20]), "no plaintext uploaded");
        let back = open_attachment(sealed.key.as_slice(), &sealed.sha256, &sealed.ciphertext).unwrap();
        assert_eq!(back.as_slice(), file.as_slice());

        let other = seal_attachment(b"something else").unwrap();
        assert_eq!(open_attachment(sealed.key.as_slice(), &sealed.sha256, &other.ciphertext).err(), Some(CoreError::Undecryptable));
        let mut bent = sealed.ciphertext.clone();
        bent[40] ^= 1;
        assert_eq!(open_attachment(sealed.key.as_slice(), &sealed.sha256, &bent).err(), Some(CoreError::Undecryptable));
        assert_eq!(open_attachment(&[0u8; 32], &sealed.sha256, &sealed.ciphertext).err(), Some(CoreError::Undecryptable));
        assert!(seal_attachment(&vec![0u8; MAX_ATTACHMENT + 1]).is_err());
    }
}
