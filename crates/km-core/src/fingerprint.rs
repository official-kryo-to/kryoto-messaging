//! Safety numbers and verification QR codes.
//!
//! Signal's published numeric fingerprint construction (iterated SHA-512 over
//! a version, the public key and a stable identifier; 5200 iterations; 30
//! digits per side), computed over each user's **master key**, so adding or
//! removing a device never changes the number. Only a master key change does.
//!
//! The key bytes carry a one-byte type tag (`0xED`, Ed25519) where Signal's
//! carry `0x05` (Curve25519), so the two can never produce colliding inputs.

use sha2::{Digest, Sha512};

use crate::error::{CoreError, Result};

const ITERATIONS: usize = 5200;
const FINGERPRINT_VERSION: [u8; 2] = [0, 0];
const KEY_TYPE_ED25519: u8 = 0xED;
const QR_VERSION: u8 = 1;

fn fingerprint(user_id: u64, master_key: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 33];
    key[0] = KEY_TYPE_ED25519;
    key[1..].copy_from_slice(master_key);
    let stable_id = user_id.to_string();

    let mut hash: [u8; 64] = Sha512::new()
        .chain_update(FINGERPRINT_VERSION)
        .chain_update(key)
        .chain_update(stable_id.as_bytes())
        .finalize()
        .into();
    for _ in 1..ITERATIONS {
        hash = Sha512::new().chain_update(hash).chain_update(key).finalize().into();
    }
    hash
}

/// 30 digits from the first 30 bytes: six 5-byte chunks, each mod 100000.
fn digits(fp: &[u8; 64]) -> String {
    fp[..30]
        .chunks(5)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            format!("{:05}", n % 100_000)
        })
        .collect()
}

/// The 60-digit safety number both people see, identical on both sides.
pub fn safety_number(a_user: u64, a_master: &[u8; 32], b_user: u64, b_master: &[u8; 32]) -> String {
    let a = digits(&fingerprint(a_user, a_master));
    let b = digits(&fingerprint(b_user, b_master));
    if a <= b {
        a + &b
    } else {
        b + &a
    }
}

/// Split into twelve groups of five, the way it is shown on screen.
pub fn display_groups(number: &str) -> Vec<&str> {
    (0..number.len()).step_by(5).map(|i| &number[i..(i + 5).min(number.len())]).collect()
}

/// What my QR code encodes: my fingerprint, then the one I hold for you.
pub fn qr_payload(my_user: u64, my_master: &[u8; 32], their_user: u64, their_master: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(QR_VERSION);
    out.extend_from_slice(&fingerprint(my_user, my_master)[..32]);
    out.extend_from_slice(&fingerprint(their_user, their_master)[..32]);
    out
}

/// Check a QR code scanned from the other person's screen. It matches when
/// their "mine" is the key I hold for them and their "yours" is my own key.
/// Compared in constant time.
pub fn verify_qr(
    scanned: &[u8],
    my_user: u64,
    my_master: &[u8; 32],
    their_user: u64,
    their_master: &[u8; 32],
) -> Result<bool> {
    if scanned.len() != 65 {
        return Err(CoreError::Malformed);
    }
    if scanned[0] != QR_VERSION {
        return Err(CoreError::UnsupportedVersion(u32::from(scanned[0])));
    }
    let expected = qr_payload(their_user, their_master, my_user, my_master);
    let diff = scanned.iter().zip(&expected).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    Ok(diff == 0)
}
