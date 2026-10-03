/// Everything that can go wrong in the core.
///
/// Messages are deliberately generic: an error can end up in a log or a bug
/// report, so it never carries key material or plaintext, and decryption
/// failures do not say *why* (that would be an oracle).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("this device has no id yet; register it first")]
    Unregistered,
    #[error("the device id is already set")]
    AlreadyRegistered,
    #[error("a signature did not verify")]
    BadSignature,
    #[error("malformed key material")]
    BadKey,
    #[error("the security key of user {user_id} changed and must be acknowledged")]
    IdentityChanged { user_id: u64 },
    #[error("no key is pinned for user {user_id}")]
    UnknownIdentity { user_id: u64 },
    #[error("no session with this device and no prekey to start one")]
    NoSession,
    #[error("the message could not be decrypted")]
    Undecryptable,
    #[error("the sending device {user_id}/{device_id} is not known")]
    UnknownSender { user_id: u64, device_id: u64 },
    #[error("malformed message")]
    Malformed,
    #[error("this message was already received")]
    Duplicate,
    #[error("the message is too large")]
    TooLarge,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("that recovery code is not right; check it and try again")]
    BadRecoveryCode,
    #[error("could not read or write saved state")]
    State,
}

pub type Result<T> = std::result::Result<T, CoreError>;
