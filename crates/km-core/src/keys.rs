//! The user master key and the certificates it issues.
//!
//! Matrix-style cross-signing: each user has one Ed25519 *master key*; every
//! device's public keys are signed by it. Contacts pin the master key (and
//! verify it with a safety number), so a new device of someone you know is
//! trusted automatically when the master key signed it, and a *changed*
//! master key is the one event that warns loudly.
//!
//! Signatures are over fixed-layout byte strings with a context prefix, never
//! over a serialisation format that could be ambiguous.

use serde::{Deserialize, Serialize};
use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

const DEVICE_CERT_CONTEXT: &[u8] = b"KRYOTO-DEVICE-CERT-V1\0";
const PREKEY_CONTEXT: &[u8] = b"KRYOTO-PREKEY-V1\0";
const GATEWAY_AUTH_CONTEXT: &[u8] = b"KRYOTO-GW-AUTH-V1\0";

/// What a device signs to prove it holds its key when connecting to the
/// gateway: a fresh server nonce, bound to the account and the device id
/// (0 when registering a new device), so a proof cannot be replayed on
/// another connection, account or device.
pub fn gateway_auth_bytes(nonce: &[u8], user_id: u64, device_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_AUTH_CONTEXT.len() + nonce.len() + 16);
    out.extend_from_slice(GATEWAY_AUTH_CONTEXT);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&user_id.to_be_bytes());
    out.extend_from_slice(&device_id.to_be_bytes());
    out
}

/// Check a gateway proof against a device's Ed25519 key.
pub fn verify_gateway_proof(
    ed25519: &[u8; 32],
    nonce: &[u8],
    user_id: u64,
    device_id: u64,
    signature: &[u8; 64],
) -> Result<()> {
    verify(ed25519, &gateway_auth_bytes(nonce, user_id, device_id), signature)
}

/// The user's master signing key. Lives only on trusted devices.
pub struct MasterKey(Ed25519SecretKey);

impl MasterKey {
    pub fn generate() -> Self {
        Self(Ed25519SecretKey::new())
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.0.public_key().as_bytes()
    }

    /// For the encrypted local store and the encrypted backup only. Never
    /// exposed to a UI.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0.to_bytes())
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(Ed25519SecretKey::from_slice(bytes))
    }

    /// Certify one device's keys.
    pub fn certify(&self, keys: &DeviceKeys) -> SignedDevice {
        let signature = self.0.sign(&keys.signing_bytes());
        SignedDevice { keys: keys.clone(), msk_signature: signature.to_bytes() }
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKind {
    Desktop = 1,
    Web = 2,
}

/// A device's public keys, as published to the directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeys {
    pub user_id: u64,
    pub device_id: u64,
    pub kind: DeviceKind,
    /// Olm signing key.
    pub ed25519: [u8; 32],
    /// Olm identity (Diffie-Hellman) key.
    pub curve25519: [u8; 32],
    /// HPKE X25519 key the sealed outer layer is encrypted to.
    pub seal_key: [u8; 32],
}

impl DeviceKeys {
    /// Fixed layout: context, user id, device id, kind, three keys.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEVICE_CERT_CONTEXT.len() + 8 + 8 + 1 + 96);
        out.extend_from_slice(DEVICE_CERT_CONTEXT);
        out.extend_from_slice(&self.user_id.to_be_bytes());
        out.extend_from_slice(&self.device_id.to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.curve25519);
        out.extend_from_slice(&self.seal_key);
        out
    }
}

/// Device keys plus the master key's signature over them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDevice {
    pub keys: DeviceKeys,
    #[serde(with = "sig_bytes")]
    pub msk_signature: [u8; 64],
}

impl SignedDevice {
    pub fn verify(&self, master_public_key: &[u8; 32]) -> Result<()> {
        verify(master_public_key, &self.keys.signing_bytes(), &self.msk_signature)
    }
}

/// A one-time or fallback prekey, signed by the device that owns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub key_id: String,
    pub key: [u8; 32],
    pub fallback: bool,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

impl SignedPrekey {
    pub(crate) fn signing_bytes(device_id: u64, fallback: bool, key: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREKEY_CONTEXT.len() + 8 + 1 + 32);
        out.extend_from_slice(PREKEY_CONTEXT);
        out.extend_from_slice(&device_id.to_be_bytes());
        out.push(u8::from(fallback));
        out.extend_from_slice(key);
        out
    }

    /// Checks the prekey was signed by the device it claims to belong to.
    pub fn verify(&self, owner: &DeviceKeys) -> Result<()> {
        let msg = Self::signing_bytes(owner.device_id, self.fallback, &self.key);
        verify(&owner.ed25519, &msg, &self.signature)
    }
}

pub(crate) fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key = Ed25519PublicKey::from_slice(public_key).map_err(|_| CoreError::BadKey)?;
    let sig = Ed25519Signature::from_slice(signature).map_err(|_| CoreError::BadSignature)?;
    key.verify(message, &sig).map_err(|_| CoreError::BadSignature)
}

/// serde has no impl for `[u8; 64]`.
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
