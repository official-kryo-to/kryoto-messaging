//! This device: its Olm account, its seal key, its sessions with other devices.
//!
//! Sending one message to a person means calling [`LocalDevice::encrypt`] once
//! per device of theirs (and once per other device of yours, so your own
//! devices stay in sync). Each call produces one opaque envelope addressed to
//! one device.
//!
//! An envelope is built in three layers:
//!
//! ```text
//! Content (the message)
//!   -> Olm (Double Ratchet with the recipient device; vodozemac)
//!   -> SealedContent { sender, olm message, padding }
//!   -> HPKE base-mode single-shot seal to the recipient's seal key (RFC 9180)
//!   -> OuterEnvelope (what the server stores)
//! ```
//!
//! The sealed layer is what keeps the sender's identity out of the server's
//! storage. It is not where authenticity comes from: the claimed sender is
//! looked up in the trust store and the Olm session must belong to that
//! device's identity key, so a forged sender field fails to decrypt.

use std::collections::{HashMap, HashSet, VecDeque};

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _,
    OpModeR, OpModeS, Serializable,
};
use km_proto::{Content, OuterEnvelope, SealedContent, ENVELOPE_VERSION};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::keys::{DeviceKeys, DeviceKind, SignedPrekey};
use crate::trust::TrustedDevice;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;
type SealSecret = <Kem as hpke::Kem>::PrivateKey;

/// HPKE `info`: binds every seal to this protocol and version.
const SEAL_INFO: &[u8] = b"KRYOTO-SEAL-V1";

/// Sizes the sealed plaintext is padded to. Chosen so the finished envelope
/// stays under the server's 64 KiB limit.
const BUCKETS: [usize; 5] = [448, 1984, 8128, 32704, 65280];

/// Olm keeps working with a handful of sessions per peer (both sides can start
/// one at the same moment); older ones are dropped.
const MAX_SESSIONS_PER_DEVICE: usize = 5;

/// How many message ids to remember for dedup.
const SEEN_CAPACITY: usize = 20_000;

/// A fresh random message id.
pub fn new_message_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("the OS random source is unavailable");
    id
}

/// A decrypted message and the device it provably came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    pub sender: DeviceKeys,
    pub content: Content,
}

pub struct LocalDevice {
    user_id: u64,
    device_id: Option<u64>,
    kind: DeviceKind,
    account: Account,
    seal_secret: SealSecret,
    seal_public: [u8; 32],
    sessions: HashMap<[u8; 32], Vec<Session>>,
    seen: SeenIds,
}

impl std::fmt::Debug for LocalDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalDevice")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl LocalDevice {
    /// A brand-new device. It has no id until the server registers it.
    pub fn new(user_id: u64, kind: DeviceKind) -> Self {
        let (seal_secret, seal_public) = Kem::gen_keypair();
        let seal_public: [u8; 32] = seal_public.to_bytes().into();
        Self {
            user_id,
            device_id: None,
            kind,
            account: Account::new(),
            seal_secret,
            seal_public,
            sessions: HashMap::new(),
            seen: SeenIds::default(),
        }
    }

    pub fn user_id(&self) -> u64 {
        self.user_id
    }

    pub fn device_id(&self) -> Option<u64> {
        self.device_id
    }

    /// Set once, after the server has registered the device.
    pub fn set_device_id(&mut self, device_id: u64) -> Result<()> {
        if self.device_id.is_some() {
            return Err(CoreError::AlreadyRegistered);
        }
        self.device_id = Some(device_id);
        Ok(())
    }

    fn require_id(&self) -> Result<u64> {
        self.device_id.ok_or(CoreError::Unregistered)
    }

    /// Public keys to register. `device_id` is 0 before registration; certify
    /// the keys only after the real id is set.
    pub fn keys(&self) -> DeviceKeys {
        let ids = self.account.identity_keys();
        DeviceKeys {
            user_id: self.user_id,
            device_id: self.device_id.unwrap_or(0),
            kind: self.kind,
            ed25519: *ids.ed25519.as_bytes(),
            curve25519: ids.curve25519.to_bytes(),
            seal_key: self.seal_public,
        }
    }

    /// Answer a gateway challenge. `device_id` is 0 while registering.
    pub fn sign_gateway_challenge(&self, nonce: &[u8], device_id: u64) -> [u8; 64] {
        self.account.sign(crate::keys::gateway_auth_bytes(nonce, self.user_id, device_id)).to_bytes()
    }

    /// New one-time prekeys (and optionally a new fallback key), signed and
    /// ready to upload. Marks them published.
    pub fn publish_prekeys(&mut self, one_time: usize, rotate_fallback: bool) -> Result<Vec<SignedPrekey>> {
        let device_id = self.require_id()?;
        if one_time > 0 {
            self.account.generate_one_time_keys(one_time);
        }
        if rotate_fallback {
            self.account.generate_fallback_key();
        }
        let mut out = Vec::new();
        for (fallback, keys) in [(false, self.account.one_time_keys()), (true, self.account.fallback_key())] {
            for (key_id, key) in keys {
                let key = key.to_bytes();
                let signature = self.account.sign(SignedPrekey::signing_bytes(device_id, fallback, &key)).to_bytes();
                out.push(SignedPrekey { key_id: key_id.to_base64(), key, fallback, signature });
            }
        }
        self.account.mark_keys_as_published();
        Ok(out)
    }

    /// How many unused one-time keys this device still holds secrets for.
    pub fn stored_one_time_keys(&self) -> usize {
        self.account.stored_one_time_key_count()
    }

    pub fn has_session(&self, with: &TrustedDevice) -> bool {
        self.sessions.get(&with.keys().curve25519).is_some_and(|s| !s.is_empty())
    }

    /// Forget every session with a device, so the next message starts a fresh
    /// one from a prekey (desync recovery).
    pub fn drop_sessions(&mut self, with: &TrustedDevice) {
        self.sessions.remove(&with.keys().curve25519);
    }

    /// Encrypt one message for one device.
    ///
    /// Uses the existing session if there is one; otherwise `prekey` (claimed
    /// from the server for that device) must be given, and is checked to be
    /// signed by the device before it is used.
    pub fn encrypt(&mut self, to: &TrustedDevice, prekey: Option<&SignedPrekey>, content: &Content) -> Result<Vec<u8>> {
        let my_id = self.require_id()?;
        if content.msg_id.len() != 16 {
            return Err(CoreError::Malformed);
        }
        let plaintext = Zeroizing::new(content.encode_to_vec());
        let curve = to.keys().curve25519;

        let sessions = self.sessions.entry(curve).or_default();
        if sessions.is_empty() {
            let prekey = prekey.ok_or(CoreError::NoSession)?;
            prekey.verify(to.keys())?;
            let session = self
                .account
                .create_outbound_session(
                    SessionConfig::version_1(),
                    Curve25519PublicKey::from_bytes(curve),
                    Curve25519PublicKey::from_bytes(prekey.key),
                )
                .map_err(|_| CoreError::BadKey)?;
            sessions.push(session);
        }
        let session = sessions.last_mut().expect("a session was just ensured");
        let olm = session.encrypt(plaintext.as_slice()).map_err(|_| CoreError::NoSession)?;
        let (olm_type, olm_body) = olm.to_parts();

        let mut sealed = SealedContent {
            sender_user_id: self.user_id,
            sender_device_id: my_id,
            olm_type: olm_type as u32,
            olm_body,
            padding: Vec::new(),
        };
        pad(&mut sealed)?;
        let sealed_bytes = Zeroizing::new(sealed.encode_to_vec());

        let recipient_key =
            <Kem as hpke::Kem>::PublicKey::from_bytes(&to.keys().seal_key).map_err(|_| CoreError::BadKey)?;
        let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
            &OpModeS::Base,
            &recipient_key,
            SEAL_INFO,
            &sealed_bytes,
            &to.keys().device_id.to_be_bytes(),
        )
        .map_err(|_| CoreError::BadKey)?;

        Ok(OuterEnvelope { version: ENVELOPE_VERSION, encapped_key: encapped.to_bytes().to_vec(), ciphertext }
            .encode_to_vec())
    }

    /// Decrypt one envelope addressed to this device.
    ///
    /// `lookup` resolves the claimed sender (user id, device id) to a device
    /// the trust store has vetted. Unknown senders fail with
    /// [`CoreError::UnknownSender`]: fetch that user's devices, check them,
    /// and try again.
    pub fn decrypt(
        &mut self,
        envelope: &[u8],
        lookup: impl FnOnce(u64, u64) -> Option<TrustedDevice>,
    ) -> Result<Inbound> {
        let my_id = self.require_id()?;
        let outer = OuterEnvelope::decode(envelope).map_err(|_| CoreError::Malformed)?;
        if outer.version != ENVELOPE_VERSION {
            return Err(CoreError::UnsupportedVersion(outer.version));
        }
        let encapped =
            <Kem as hpke::Kem>::EncappedKey::from_bytes(&outer.encapped_key).map_err(|_| CoreError::Malformed)?;
        let sealed_bytes = Zeroizing::new(
            hpke::single_shot_open::<Aead, Kdf, Kem>(
                &OpModeR::Base,
                &self.seal_secret,
                &encapped,
                SEAL_INFO,
                &outer.ciphertext,
                &my_id.to_be_bytes(),
            )
            .map_err(|_| CoreError::Undecryptable)?,
        );
        let sealed = SealedContent::decode(sealed_bytes.as_slice()).map_err(|_| CoreError::Malformed)?;

        let (user_id, device_id) = (sealed.sender_user_id, sealed.sender_device_id);
        let sender = lookup(user_id, device_id).ok_or(CoreError::UnknownSender { user_id, device_id })?;
        if sender.keys().user_id != user_id || sender.keys().device_id != device_id {
            return Err(CoreError::Undecryptable);
        }
        let curve = sender.keys().curve25519;
        let olm = OlmMessage::from_parts(sealed.olm_type as usize, &sealed.olm_body).map_err(|_| CoreError::Malformed)?;

        let plaintext = Zeroizing::new(self.olm_decrypt(curve, &olm)?);
        let content = Content::decode(plaintext.as_slice()).map_err(|_| CoreError::Malformed)?;
        let msg_id: [u8; 16] = content.msg_id.as_slice().try_into().map_err(|_| CoreError::Malformed)?;
        if !self.seen.insert(msg_id) {
            return Err(CoreError::Duplicate);
        }
        Ok(Inbound { sender: sender.keys().clone(), content })
    }

    fn olm_decrypt(&mut self, curve: [u8; 32], olm: &OlmMessage) -> Result<Vec<u8>> {
        let sessions = self.sessions.entry(curve).or_default();
        match olm {
            OlmMessage::PreKey(m) => {
                // A pre-key message for a session we already have: the sender
                // keeps sending pre-key messages until it hears back from us.
                let id = m.session_id();
                if let Some(pos) = sessions.iter().position(|s| s.session_id() == id) {
                    let pt = sessions[pos].decrypt(olm).map_err(|_| CoreError::Undecryptable)?;
                    let s = sessions.remove(pos);
                    sessions.push(s);
                    return Ok(pt);
                }
                // The identity key inside the pre-key message must be the one
                // the claimed sender owns. vodozemac checks it too.
                if m.identity_key().to_bytes() != curve {
                    return Err(CoreError::Undecryptable);
                }
                let created = self
                    .account
                    .create_inbound_session(SessionConfig::version_1(), Curve25519PublicKey::from_bytes(curve), m)
                    .map_err(|_| CoreError::Undecryptable)?;
                sessions.push(created.session);
                if sessions.len() > MAX_SESSIONS_PER_DEVICE {
                    sessions.remove(0);
                }
                Ok(created.plaintext)
            }
            OlmMessage::Normal(_) => {
                for pos in (0..sessions.len()).rev() {
                    if let Ok(pt) = sessions[pos].decrypt(olm) {
                        let s = sessions.remove(pos);
                        sessions.push(s);
                        return Ok(pt);
                    }
                }
                Err(CoreError::Undecryptable)
            }
        }
    }

    /// Everything needed to restore this device later. Contains secrets: store
    /// it only inside the encrypted local database.
    pub fn snapshot(&self) -> Result<Zeroizing<String>> {
        let snap = DeviceSnapshot {
            format: 1,
            user_id: self.user_id,
            device_id: self.device_id,
            kind: self.kind,
            account: self.account.pickle(),
            seal_secret: Zeroizing::new(self.seal_secret.to_bytes().to_vec()),
            sessions: self
                .sessions
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (*k, v.iter().map(Session::pickle).collect()))
                .collect(),
            seen: self.seen.order.iter().copied().collect(),
        };
        serde_json::to_string(&snap).map(Zeroizing::new).map_err(|_| CoreError::State)
    }

    pub fn restore(snapshot: &str) -> Result<Self> {
        let snap: DeviceSnapshot = serde_json::from_str(snapshot).map_err(|_| CoreError::State)?;
        if snap.format != 1 {
            return Err(CoreError::UnsupportedVersion(snap.format));
        }
        let seal_secret = SealSecret::from_bytes(&snap.seal_secret).map_err(|_| CoreError::State)?;
        let seal_public: [u8; 32] = Kem::sk_to_pk(&seal_secret).to_bytes().into();
        let mut seen = SeenIds::default();
        for id in snap.seen {
            seen.insert(id);
        }
        Ok(Self {
            user_id: snap.user_id,
            device_id: snap.device_id,
            kind: snap.kind,
            account: Account::from_pickle(snap.account),
            seal_secret,
            seal_public,
            sessions: snap
                .sessions
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(Session::from_pickle).collect()))
                .collect(),
            seen,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceSnapshot {
    format: u32,
    user_id: u64,
    device_id: Option<u64>,
    kind: DeviceKind,
    account: AccountPickle,
    seal_secret: Zeroizing<Vec<u8>>,
    sessions: Vec<([u8; 32], Vec<SessionPickle>)>,
    seen: Vec<[u8; 16]>,
}

/// Bounded set of message ids already delivered.
#[derive(Default)]
struct SeenIds {
    set: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}

impl SeenIds {
    fn insert(&mut self, id: [u8; 16]) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > SEEN_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// Pad `sealed` with zero bytes so its encoding is exactly a bucket size.
fn pad(sealed: &mut SealedContent) -> Result<()> {
    sealed.padding.clear();
    let base = sealed.encoded_len();
    for &target in BUCKETS.iter().filter(|&&b| b > base) {
        // The padding field costs one key byte, a length varint, and itself.
        let need = target - base - 1;
        let fit = (need.saturating_sub(3)..=need)
            .rev()
            .find(|&p| prost::encoding::encoded_len_varint(p as u64) + p == need);
        if let Some(p) = fit {
            sealed.padding = vec![0u8; p];
            debug_assert_eq!(sealed.encoded_len(), target);
            return Ok(());
        }
    }
    Err(CoreError::TooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_lands_on_a_bucket() {
        for len in [0usize, 1, 100, 125, 126, 127, 128, 400, 446, 1500, 16_000, 32_000, 64_000] {
            let mut s = SealedContent {
                sender_user_id: u64::MAX,
                sender_device_id: u64::MAX,
                olm_type: 1,
                olm_body: vec![7; len],
                padding: vec![],
            };
            if pad(&mut s).is_ok() {
                assert!(BUCKETS.contains(&s.encoded_len()), "len {len} -> {}", s.encoded_len());
            } else {
                assert!(len > 65_000);
            }
        }
    }
}
