//! Wire formats for Kryoto chat.
//!
//! Hand-written `prost` messages (no `protoc` needed to build). Tags are a
//! compatibility promise: never reuse or renumber one; add new fields with new
//! tags. Unknown fields are ignored by older clients, which is how new message
//! kinds roll out without breaking anybody.
//!
//! Three layers, outermost first:
//!
//! 1. [`OuterEnvelope`] - what the server stores and forwards. Opaque.
//! 2. [`SealedContent`] - HPKE-sealed to the recipient device. Names the
//!    sender, carries the Olm message, and is padded to a size bucket.
//! 3. [`Content`] - the Olm plaintext: what the person actually sent.

pub mod gateway;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u32 = 1;

/// What the gateway stores in a device's inbox. It can read none of it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OuterEnvelope {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// HPKE encapsulated key (X25519, 32 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub encapped_key: Vec<u8>,
    /// HPKE ciphertext of an encoded [`SealedContent`].
    #[prost(bytes = "vec", tag = "3")]
    pub ciphertext: Vec<u8>,
}

/// The sealed layer. Only the recipient device can open it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SealedContent {
    #[prost(uint64, tag = "1")]
    pub sender_user_id: u64,
    #[prost(uint64, tag = "2")]
    pub sender_device_id: u64,
    /// Olm message type: 0 = pre-key, 1 = normal (vodozemac's numbering).
    #[prost(uint32, tag = "3")]
    pub olm_type: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub olm_body: Vec<u8>,
    /// Zero bytes that round the encoded size up to a bucket, so the
    /// ciphertext length says little about what is inside.
    #[prost(bytes = "vec", tag = "15")]
    pub padding: Vec<u8>,
}

/// The plaintext of one chat message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Content {
    /// 16 random bytes, chosen by the sender. Used for dedup, receipts,
    /// replies, edits and deletes.
    #[prost(bytes = "vec", tag = "1")]
    pub msg_id: Vec<u8>,
    /// Which conversation this belongs to, as the clients name it.
    #[prost(bytes = "vec", tag = "2")]
    pub conversation_id: Vec<u8>,
    /// Sender's clock, milliseconds since the Unix epoch. The server never
    /// records a send time, so this is the only one there is.
    #[prost(uint64, tag = "3")]
    pub sent_at_ms: u64,
    #[prost(oneof = "content::Body", tags = "10, 11, 12, 13, 14, 15, 16")]
    pub body: Option<content::Body>,
}

pub mod content {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        Text(super::Text),
        #[prost(message, tag = "11")]
        Receipt(super::Receipt),
        #[prost(message, tag = "12")]
        Typing(super::Typing),
        #[prost(message, tag = "13")]
        Edit(super::Edit),
        #[prost(message, tag = "14")]
        Delete(super::Delete),
        #[prost(message, tag = "15")]
        Reaction(super::Reaction),
        #[prost(message, tag = "16")]
        Gif(super::Gif),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Text {
    #[prost(string, tag = "1")]
    pub text: String,
    /// msg_id of the message this replies to, or empty.
    #[prost(bytes = "vec", tag = "2")]
    pub reply_to: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ReceiptKind {
    Unspecified = 0,
    Delivered = 1,
    Read = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Receipt {
    #[prost(enumeration = "ReceiptKind", tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub msg_ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Typing {
    #[prost(bool, tag = "1")]
    pub active: bool,
}

/// Replace the text of one of your own earlier messages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Edit {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub text: String,
}

/// Delete one of your own earlier messages for everyone.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Delete {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
}

/// Add (or, with `remove`, take back) an emoji reaction to a message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reaction {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub emoji: String,
    #[prost(bool, tag = "3")]
    pub remove: bool,
}

/// A GIF from a public GIF provider: the message carries where to load it
/// from, never the file. Receivers only load `url` from the provider's own
/// media host (km-core `gif_url_allowed`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gif {
    /// "giphy" or "klipy".
    #[prost(string, tag = "1")]
    pub provider: String,
    #[prost(string, tag = "2")]
    pub id: String,
    #[prost(string, tag = "3")]
    pub url: String,
    #[prost(uint32, tag = "4")]
    pub width: u32,
    #[prost(uint32, tag = "5")]
    pub height: u32,
    /// Shown while loading, and to readers who turned automatic GIFs off.
    #[prost(string, tag = "6")]
    pub title: String,
}
