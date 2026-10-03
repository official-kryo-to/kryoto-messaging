//! The optional key backup: the account's master key and trust pins, sealed
//! under a recovery code only the person holds, stored on the server as an
//! opaque blob.
//!
//! - **Recovery code:** 240 random bits plus a 16-bit checksum, written as 52
//!   Crockford base32 characters in groups of four. The checksum catches a
//!   mistyped code before anything is fetched or tried.
//! - **Sealing:** XChaCha20-Poly1305 with a key derived from the code
//!   (SHA-256 with a domain label; the code is already full-entropy, so no
//!   password hashing is needed), a random 24-byte nonce, and the account id
//!   in the associated data so a blob cannot be replayed onto another account.
//! - **Never in a backup:** Olm sessions or device keys. A restored device is a
//!   new device that the restored master key certifies (restoring ratchets
//!   would desynchronise them).
//!
//! Lose the code and every device, and the identity is gone: nobody, staff
//! included, can open the blob.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};
use crate::keys::MasterKey;
use crate::trust::TrustStore;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_LEN: usize = 30;
const CODE_LEN: usize = 52;
const BLOB_VERSION: u8 = 1;
const AAD_LABEL: &[u8] = b"KRYOTO-BACKUP-V1";
const KEY_LABEL: &[u8] = b"KRYOTO-BACKUP-KEY-V1";

/// The secret behind a recovery code. Shown once; kept by the person.
pub struct RecoveryKey(Zeroizing<[u8; SECRET_LEN]>);

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(secret.as_mut_slice()).expect("the system random source failed");
        Self(secret)
    }

    /// `XXXX-XXXX-...` (13 groups of 4).
    pub fn to_code(&self) -> String {
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN + 2]);
        bytes[..SECRET_LEN].copy_from_slice(self.0.as_slice());
        bytes[SECRET_LEN..].copy_from_slice(&checksum(self.0.as_slice()));
        let chars = encode(bytes.as_slice());
        chars.chunks(4).map(|c| std::str::from_utf8(c).expect("ascii")).collect::<Vec<_>>().join("-")
    }

    /// Accepts the code as written, in any case, with or without separators,
    /// and with the usual look-alikes (I, L -> 1; O -> 0).
    pub fn from_code(code: &str) -> Result<Self> {
        let mut clean: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(CODE_LEN));
        for c in code.bytes() {
            match c {
                b'-' | b' ' | b'\t' | b'\n' | b'\r' => continue,
                b'I' | b'i' | b'L' | b'l' => clean.push(b'1'),
                b'O' | b'o' => clean.push(b'0'),
                c => clean.push(c.to_ascii_uppercase()),
            }
        }
        if clean.len() != CODE_LEN {
            return Err(CoreError::BadRecoveryCode);
        }
        let bytes = decode(&clean).ok_or(CoreError::BadRecoveryCode)?;
        let (secret, check) = bytes.split_at(SECRET_LEN);
        if checksum(secret) != check {
            return Err(CoreError::BadRecoveryCode);
        }
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        out.copy_from_slice(secret);
        Ok(Self(out))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let mut h = Sha256::new();
        h.update(KEY_LABEL);
        h.update(self.0.as_slice());
        let mut key: [u8; 32] = h.finalize().into();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
        key.zeroize();
        cipher
    }
}

fn checksum(secret: &[u8]) -> [u8; 2] {
    let d = Sha256::digest(secret);
    [d[0], d[1]]
}

/// 32 bytes (256 bits) -> 52 characters; the last one carries 1 real bit and
/// 4 bits of zero padding.
fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CODE_LEN);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    }
    acc.zeroize();
    out
}

fn decode(chars: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(SECRET_LEN + 2));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in chars {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // The padding bits must be zero: one code, one spelling.
    if acc & ((1 << bits) - 1) != 0 || out.len() != SECRET_LEN + 2 {
        return None;
    }
    acc.zeroize();
    Some(out)
}

#[derive(Serialize, Deserialize)]
struct Contents {
    v: u32,
    user_id: u64,
    master: String,
    trust: TrustStore,
}

impl Drop for Contents {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

fn aad(user_id: u64) -> Vec<u8> {
    let mut a = AAD_LABEL.to_vec();
    a.extend_from_slice(&user_id.to_be_bytes());
    a
}

/// Seal the master key and trust pins for upload.
pub fn seal_backup(key: &RecoveryKey, user_id: u64, master: &MasterKey, trust: &TrustStore) -> Result<Vec<u8>> {
    let contents = Contents { v: 1, user_id, master: hex_encode(master.to_secret_bytes().as_slice()), trust: trust.clone() };
    let plain = Zeroizing::new(serde_json::to_vec(&contents).map_err(|_| CoreError::State)?);
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CoreError::State)?;
    let aad = aad(user_id);
    let sealed = key
        .cipher()
        .encrypt(&XNonce::from(nonce), Payload { msg: plain.as_slice(), aad: &aad })
        .map_err(|_| CoreError::State)?;
    let mut blob = Vec::with_capacity(1 + 24 + sealed.len());
    blob.push(BLOB_VERSION);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Open a backup. A wrong code and a damaged blob fail the same way.
pub fn open_backup(key: &RecoveryKey, user_id: u64, blob: &[u8]) -> Result<(MasterKey, TrustStore)> {
    if blob.len() < 1 + 24 + 16 {
        return Err(CoreError::Malformed);
    }
    if blob[0] != BLOB_VERSION {
        return Err(CoreError::UnsupportedVersion(u32::from(blob[0])));
    }
    let nonce: [u8; 24] = blob[1..25].try_into().map_err(|_| CoreError::Malformed)?;
    let aad = aad(user_id);
    let plain = Zeroizing::new(
        key.cipher()
            .decrypt(&XNonce::from(nonce), Payload { msg: &blob[25..], aad: &aad })
            .map_err(|_| CoreError::Undecryptable)?,
    );
    let contents: Contents = serde_json::from_slice(&plain).map_err(|_| CoreError::Malformed)?;
    if contents.v != 1 || contents.user_id != user_id {
        return Err(CoreError::Malformed);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    hex_decode(&contents.master, secret.as_mut_slice()).ok_or(CoreError::Malformed)?;
    Ok((MasterKey::from_secret_bytes(&secret), contents.trust.clone()))
}

fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn hex_decode(s: &str, out: &mut [u8]) -> Option<()> {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 {
        return None;
    }
    let v = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    for (i, o) in out.iter_mut().enumerate() {
        *o = (v(b[2 * i])? << 4) | v(b[2 * i + 1])?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_forgive_how_they_are_typed() {
        let k = RecoveryKey::generate();
        let code = k.to_code();
        assert_eq!(code.len(), 52 + 12, "13 groups of 4 with dashes: {code}");
        assert!(code.bytes().all(|c| c == b'-' || ALPHABET.contains(&c)));
        let back = RecoveryKey::from_code(&code.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(back.0.as_slice(), k.0.as_slice());
        let looks = code.replace('1', "l").replace('0', "o");
        assert_eq!(RecoveryKey::from_code(&looks).unwrap().0.as_slice(), k.0.as_slice());
    }

    #[test]
    fn a_typo_is_caught_by_the_checksum() {
        let code = RecoveryKey::generate().to_code();
        let mut chars: Vec<char> = code.chars().collect();
        let i = chars.iter().position(|c| *c != '-').unwrap();
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(RecoveryKey::from_code(&typo), Err(CoreError::BadRecoveryCode)));
        assert!(matches!(RecoveryKey::from_code("ABCD"), Err(CoreError::BadRecoveryCode)));
        assert!(matches!(RecoveryKey::from_code(&format!("{code}U")), Err(CoreError::BadRecoveryCode)));
    }

    #[test]
    fn backup_round_trip_and_wrong_code_or_account_fails() {
        let master = MasterKey::generate();
        let mut trust = TrustStore::new();
        trust.pin_own(7, master.public_key());
        let key = RecoveryKey::generate();
        let blob = seal_backup(&key, 7, &master, &trust).unwrap();
        let (m, t) = open_backup(&key, 7, &blob).unwrap();
        assert_eq!(m.public_key(), master.public_key());
        assert_eq!(t.pinned(7).map(|p| p.0), Some(master.public_key()));
        assert_eq!(open_backup(&RecoveryKey::generate(), 7, &blob).err(), Some(CoreError::Undecryptable));
        assert_eq!(open_backup(&key, 8, &blob).err(), Some(CoreError::Undecryptable), "bound to the account");
        let mut bent = blob.clone();
        *bent.last_mut().unwrap() ^= 1;
        assert_eq!(open_backup(&key, 7, &bent).err(), Some(CoreError::Undecryptable));
        assert!(!blob.windows(32).any(|w| w == master.to_secret_bytes().as_slice()), "no plaintext key in the blob");
    }
}
