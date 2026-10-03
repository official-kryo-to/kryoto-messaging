//! The WebSocket protocol between a client device and `kryoto-gateway`.
//!
//! Every WebSocket binary message is exactly one [`ClientFrame`] or
//! [`ServerFrame`]. A client sets `request_id` on a request and the server
//! echoes it on the answer; server-initiated frames (deliveries, events)
//! carry `request_id = 0`.
//!
//! Connection:
//!
//! ```text
//! C: Hello { token, device_id (0 = new device) }
//! S: Challenge { nonce }
//! C: Proof { signature }                      existing device
//!  | RegisterDevice { keys, signature }       new device (signs with its new key)
//! S: Registered { device_id }                 new device only
//! S: Ready { ... }
//! S: Deliver { seq, envelope } ...            backlog, then live
//! C: Ack { up_to_seq }
//! ```

/// Bump on breaking changes; the server refuses clients below its minimum.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientFrame {
    #[prost(uint32, tag = "1")]
    pub request_id: u32,
    #[prost(
        oneof = "client_frame::Kind",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24"
    )]
    pub kind: Option<client_frame::Kind>,
}

pub mod client_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "10")]
        Hello(super::Hello),
        #[prost(message, tag = "11")]
        Proof(super::Proof),
        #[prost(message, tag = "12")]
        RegisterDevice(super::RegisterDevice),
        #[prost(message, tag = "13")]
        PublishMasterKey(super::PublishMasterKey),
        #[prost(message, tag = "14")]
        CertifyDevice(super::CertifyDevice),
        #[prost(message, tag = "15")]
        KeysUpload(super::KeysUpload),
        #[prost(message, tag = "16")]
        DevicesQuery(super::DevicesQuery),
        #[prost(message, tag = "17")]
        KeysClaim(super::KeysClaim),
        #[prost(message, tag = "18")]
        Send(super::Send),
        #[prost(message, tag = "19")]
        Ack(super::Ack),
        #[prost(message, tag = "20")]
        RevokeDevice(super::RevokeDevice),
        #[prost(message, tag = "21")]
        BackupPut(super::BackupPut),
        #[prost(message, tag = "22")]
        BackupGet(super::Empty),
        #[prost(message, tag = "23")]
        BackupDelete(super::Empty),
        #[prost(message, tag = "24")]
        ListMyDevices(super::Empty),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerFrame {
    #[prost(uint32, tag = "1")]
    pub request_id: u32,
    #[prost(
        oneof = "server_frame::Kind",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22"
    )]
    pub kind: Option<server_frame::Kind>,
}

pub mod server_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "10")]
        Challenge(super::Challenge),
        #[prost(message, tag = "11")]
        Registered(super::Registered),
        #[prost(message, tag = "12")]
        Ready(super::Ready),
        #[prost(message, tag = "13")]
        Error(super::Error),
        #[prost(message, tag = "14")]
        Ok(super::Empty),
        #[prost(message, tag = "15")]
        KeysCount(super::KeysCount),
        #[prost(message, tag = "16")]
        Devices(super::Devices),
        #[prost(message, tag = "17")]
        KeysBundle(super::KeysBundle),
        #[prost(message, tag = "18")]
        SendAck(super::SendAck),
        #[prost(message, tag = "19")]
        Deliver(super::Deliver),
        #[prost(message, tag = "20")]
        Event(super::Event),
        #[prost(message, tag = "21")]
        Backup(super::Backup),
        #[prost(message, tag = "22")]
        DeviceList(super::DeviceList),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}

// ---- handshake ------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hello {
    /// The kryo.to session token (never a cookie: a WebSocket from another
    /// origin cannot ride along on it).
    #[prost(string, tag = "1")]
    pub token: String,
    #[prost(uint32, tag = "2")]
    pub protocol_version: u32,
    /// This device's id, or 0 to register a new device.
    #[prost(uint64, tag = "3")]
    pub device_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Challenge {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
}

/// Ed25519 signature by the device key over km-core's gateway auth bytes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Proof {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDevice {
    /// 1 = desktop, 2 = web.
    #[prost(uint32, tag = "1")]
    pub kind: u32,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(bytes = "vec", tag = "3")]
    pub ed25519: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub curve25519: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub seal_key: Vec<u8>,
    /// Proof over the challenge with device id 0, by the new `ed25519` key.
    #[prost(bytes = "vec", tag = "6")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Registered {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ready {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
    #[prost(uint64, tag = "2")]
    pub device_id: u64,
    /// One-time keys the server still holds for this device.
    #[prost(uint32, tag = "3")]
    pub one_time_keys: u32,
    #[prost(bool, tag = "4")]
    pub has_fallback_key: bool,
    /// Whether this device carries a valid master-key certificate. Until it
    /// does, nobody else can see it or send to it.
    #[prost(bool, tag = "5")]
    pub certified: bool,
    /// The user's current master key, empty if none was published yet.
    #[prost(bytes = "vec", tag = "6")]
    pub master_key: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub min_protocol_version: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Error {
    /// Stable machine code: unauthorized, device_unknown, anonymous_mode, chat_disabled,
    /// bad_request, forbidden, not_found, conflict, rate_limited,
    /// unsupported_version, replaced, internal.
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub message: String,
}

// ---- keys -----------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublishMasterKey {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,
}

/// Master-key signature over a device's keys (km-core DeviceKeys).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertifyDevice {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Prekey {
    #[prost(string, tag = "1")]
    pub key_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    #[prost(bool, tag = "3")]
    pub fallback: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysUpload {
    #[prost(message, repeated, tag = "1")]
    pub prekeys: Vec<Prekey>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysCount {
    #[prost(uint32, tag = "1")]
    pub one_time_keys: u32,
    #[prost(bool, tag = "2")]
    pub has_fallback_key: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DevicesQuery {
    #[prost(uint64, repeated, tag = "1")]
    pub user_ids: Vec<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceInfo {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub ed25519: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub curve25519: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub seal_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub msk_signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserDevicesInfo {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub master_key: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub devices: Vec<DeviceInfo>,
}

/// Users the caller may not see are simply absent.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Devices {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserDevicesInfo>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysClaim {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimedKey {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
    #[prost(message, optional, tag = "2")]
    pub prekey: Option<Prekey>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysBundle {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
    #[prost(message, repeated, tag = "2")]
    pub keys: Vec<ClaimedKey>,
}

// ---- messages -------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendItem {
    #[prost(uint64, tag = "1")]
    pub recipient_device_id: u64,
    /// A km-proto OuterEnvelope, encoded.
    #[prost(bytes = "vec", tag = "2")]
    pub envelope: Vec<u8>,
}

/// One message to everybody who should get it: every device of every
/// recipient user, plus the sender's own other devices.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Send {
    /// 16 random bytes. A retried Send with the same id gets the same answer.
    #[prost(bytes = "vec", tag = "1")]
    pub client_msg_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub items: Vec<SendItem>,
    /// Typing indicators and the like: delivered to online devices only,
    /// never stored.
    #[prost(bool, tag = "3")]
    pub ephemeral: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SendStatus {
    Unspecified = 0,
    Accepted = 1,
    /// The device list is out of date: see missing/stale, refetch, resend.
    DeviceMismatch = 2,
    Forbidden = 3,
    RateLimited = 4,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendAck {
    #[prost(bytes = "vec", tag = "1")]
    pub client_msg_id: Vec<u8>,
    #[prost(enumeration = "SendStatus", tag = "2")]
    pub status: i32,
    /// Devices that should have been included and were not.
    #[prost(uint64, repeated, tag = "3")]
    pub missing_device_ids: Vec<u64>,
    /// Devices that were included but no longer exist.
    #[prost(uint64, repeated, tag = "4")]
    pub stale_device_ids: Vec<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Deliver {
    /// Inbox position; 0 for an ephemeral delivery (do not ack those).
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub envelope: Vec<u8>,
}

/// Everything up to and including this seq has been stored by the client and
/// may be deleted from the server.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ack {
    #[prost(uint64, tag = "1")]
    pub up_to_seq: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeDevice {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EventKind {
    Unspecified = 0,
    /// The user's device list changed (added, certified, revoked).
    DevicesChanged = 1,
    /// The user's master key changed.
    MasterKeyChanged = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Event {
    #[prost(enumeration = "EventKind", tag = "1")]
    pub kind: i32,
    #[prost(uint64, tag = "2")]
    pub user_id: u64,
}

// ---- key backup -----------------------------------------------------------

/// Store (or replace) this account's key backup: an opaque blob sealed on the
/// client under a recovery code the server never sees (km-core `seal_backup`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupPut {
    #[prost(bytes = "vec", tag = "1")]
    pub blob: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Backup {
    /// Empty when the account has no backup.
    #[prost(bytes = "vec", tag = "1")]
    pub blob: Vec<u8>,
    #[prost(int64, tag = "2")]
    pub updated_at_ms: i64,
}

// ---- own devices ----------------------------------------------------------

/// One of the caller's own devices, with what only its owner sees.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MyDevice {
    #[prost(uint64, tag = "1")]
    pub device_id: u64,
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    #[prost(string, tag = "3")]
    pub name: String,
    /// Certified by the current master key (reachable by others).
    #[prost(bool, tag = "4")]
    pub certified: bool,
    #[prost(int64, tag = "5")]
    pub created_at_ms: i64,
    /// Day granularity, 0 if never.
    #[prost(int64, tag = "6")]
    pub last_seen_day_ms: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceList {
    #[prost(message, repeated, tag = "1")]
    pub devices: Vec<MyDevice>,
}
