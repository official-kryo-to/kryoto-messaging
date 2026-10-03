//! Chat rules every client applies the same way: conversation ids, message
//! limits, which GIF addresses may be loaded, and what a receiver does with a
//! message that breaks the rules.
//!
//! The server cannot read messages, so it cannot enforce any of this. The
//! sending client applies the limits; every receiving client applies them
//! again against what it knows about the sender (supporter or not), so a
//! modified client gains nothing by ignoring them.

use km_proto::{content::Body, Content};

use crate::error::{CoreError, Result};

/// Characters in a message (and an edit) for everyone...
pub const TEXT_LIMIT: usize = 2_000;
/// ...and for supporters.
pub const SUPPORTER_TEXT_LIMIT: usize = 8_000;
/// A reaction is one emoji; a few code points cover flags and skin tones.
pub const REACTION_LIMIT: usize = 16;
/// How long after sending a message can still be edited or deleted for everyone.
pub const EDIT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

pub fn text_limit(supporter: bool) -> usize {
    if supporter {
        SUPPORTER_TEXT_LIMIT
    } else {
        TEXT_LIMIT
    }
}

/// The id of the 1:1 conversation between two accounts: the same on both
/// sides, whoever sends.
pub fn dm_conversation_id(a: u64, b: u64) -> Vec<u8> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut id = Vec::with_capacity(19);
    id.extend_from_slice(b"dm:");
    id.extend_from_slice(&lo.to_be_bytes());
    id.extend_from_slice(&hi.to_be_bytes());
    id
}

/// The other account in a 1:1 conversation, if `me` is in it.
pub fn dm_peer(conversation_id: &[u8], me: u64) -> Option<u64> {
    if conversation_id.len() != 19 || &conversation_id[..3] != b"dm:" {
        return None;
    }
    let lo = u64::from_be_bytes(conversation_id[3..11].try_into().ok()?);
    let hi = u64::from_be_bytes(conversation_id[11..19].try_into().ok()?);
    match (lo == me, hi == me) {
        (true, _) => Some(hi),
        (_, true) => Some(lo),
        _ => None,
    }
}

/// Media hosts each GIF provider serves from. Anything else is never loaded:
/// a message must not be able to make your app fetch an arbitrary address.
fn gif_host_allowed(provider: &str, host: &str) -> bool {
    let under = |root: &str| host == root || host.ends_with(&format!(".{root}"));
    match provider {
        "giphy" => under("giphy.com"),
        "klipy" => under("klipy.com"),
        _ => false,
    }
}

/// `https://<allowed host>/<path>` and nothing cleverer: no credentials, no
/// port, no other scheme.
pub fn gif_url_allowed(provider: &str, url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains(['@', ':']) || url.len() > 512 {
        return false;
    }
    gif_host_allowed(provider, &host.to_ascii_lowercase())
}

/// Check a message before sending it. `supporter` is the sender's own status.
pub fn validate_outgoing(content: &Content, supporter: bool) -> Result<()> {
    let limit = text_limit(supporter);
    let too_long = |s: &str| s.chars().count() > limit;
    match &content.body {
        Some(Body::Text(t)) => {
            if t.text.trim().is_empty() {
                return Err(CoreError::Malformed);
            }
            if too_long(&t.text) {
                return Err(CoreError::TooLarge);
            }
        }
        Some(Body::Edit(e)) => {
            if e.target.len() != 16 || e.text.trim().is_empty() {
                return Err(CoreError::Malformed);
            }
            if too_long(&e.text) {
                return Err(CoreError::TooLarge);
            }
        }
        Some(Body::Delete(d)) if d.target.len() != 16 => return Err(CoreError::Malformed),
        Some(Body::Reaction(r)) => {
            if r.target.len() != 16 || r.emoji.is_empty() || r.emoji.chars().count() > REACTION_LIMIT {
                return Err(CoreError::Malformed);
            }
        }
        Some(Body::Gif(g)) => {
            // GIFs are a supporter perk.
            if !supporter {
                return Err(CoreError::Malformed);
            }
            if !gif_url_allowed(&g.provider, &g.url) {
                return Err(CoreError::Malformed);
            }
        }
        _ => {}
    }
    Ok(())
}

/// What a receiver shows for an incoming message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// Within the rules.
    Ok,
    /// Text cut to the sender's limit (they are not a supporter, or a client
    /// sent more than anyone may).
    Truncated(String),
    /// A GIF from a non-supporter, or from a host that is not the provider's:
    /// shown as plain text, never loaded.
    GifAsText(String),
}

/// Apply the rules on the receiving side. `sender_supporter` comes from the
/// sender's public profile, not from anything inside the message.
pub fn receive_rules(content: &Content, sender_supporter: bool) -> Shown {
    let limit = text_limit(sender_supporter);
    let cut = |s: &str| -> Option<String> {
        (s.chars().count() > limit).then(|| s.chars().take(limit).collect())
    };
    match &content.body {
        Some(Body::Text(t)) => cut(&t.text).map(Shown::Truncated).unwrap_or(Shown::Ok),
        Some(Body::Edit(e)) => cut(&e.text).map(Shown::Truncated).unwrap_or(Shown::Ok),
        Some(Body::Gif(g)) if !sender_supporter || !gif_url_allowed(&g.provider, &g.url) => {
            let label = if g.title.trim().is_empty() { "GIF".to_string() } else { format!("GIF: {}", g.title.trim()) };
            Shown::GifAsText(label.chars().take(200).collect())
        }
        _ => Shown::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_proto::{Gif, Reaction, Text};

    fn content(body: Body) -> Content {
        Content { msg_id: vec![1; 16], conversation_id: vec![], sent_at_ms: 0, body: Some(body) }
    }

    #[test]
    fn dm_ids_match_on_both_sides() {
        assert_eq!(dm_conversation_id(5, 9), dm_conversation_id(9, 5));
        assert_ne!(dm_conversation_id(5, 9), dm_conversation_id(5, 10));
        let id = dm_conversation_id(5, 9);
        assert_eq!(dm_peer(&id, 5), Some(9));
        assert_eq!(dm_peer(&id, 9), Some(5));
        assert_eq!(dm_peer(&id, 7), None, "not your conversation");
        assert_eq!(dm_peer(b"group:xyz", 5), None);
    }

    #[test]
    fn length_limits_depend_on_supporting() {
        let long = content(Body::Text(Text { text: "x".repeat(3000), reply_to: vec![] }));
        assert_eq!(validate_outgoing(&long, false), Err(CoreError::TooLarge));
        assert!(validate_outgoing(&long, true).is_ok());
        let huge = content(Body::Text(Text { text: "x".repeat(8001), reply_to: vec![] }));
        assert_eq!(validate_outgoing(&huge, true), Err(CoreError::TooLarge));
        // Characters, not bytes: 2000 emoji are fine.
        let emoji = content(Body::Text(Text { text: "😀".repeat(2000), reply_to: vec![] }));
        assert!(validate_outgoing(&emoji, false).is_ok());
    }

    #[test]
    fn receivers_cut_what_the_sender_may_not_send() {
        let long = content(Body::Text(Text { text: "y".repeat(3000), reply_to: vec![] }));
        assert_eq!(receive_rules(&long, true), Shown::Ok);
        match receive_rules(&long, false) {
            Shown::Truncated(t) => assert_eq!(t.chars().count(), TEXT_LIMIT),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn gifs_are_for_supporters_and_only_from_the_provider() {
        let gif = |url: &str| {
            content(Body::Gif(Gif {
                provider: "giphy".into(),
                id: "abc".into(),
                url: url.into(),
                width: 200,
                height: 200,
                title: "cat".into(),
            }))
        };
        let good = gif("https://media2.giphy.com/media/abc/giphy.webp");
        assert!(validate_outgoing(&good, true).is_ok());
        assert!(validate_outgoing(&good, false).is_err(), "not a supporter");
        assert_eq!(receive_rules(&good, true), Shown::Ok);
        assert_eq!(receive_rules(&good, false), Shown::GifAsText("GIF: cat".into()));
        for bad in [
            "http://media.giphy.com/x.gif",
            "https://evil.example/x.gif",
            "https://giphy.com.evil.example/x.gif",
            "https://user@media.giphy.com/x.gif",
            "https://media.giphy.com:8443/x.gif",
            "javascript:alert(1)",
        ] {
            assert!(!gif_url_allowed("giphy", bad), "{bad}");
            assert!(matches!(receive_rules(&gif(bad), true), Shown::GifAsText(_)), "{bad}");
        }
        assert!(gif_url_allowed("klipy", "https://static.klipy.com/a.gif"));
        assert!(!gif_url_allowed("tenor", "https://media.tenor.com/a.gif"));
    }

    #[test]
    fn reactions_are_small() {
        let r = |e: &str| content(Body::Reaction(Reaction { target: vec![2; 16], emoji: e.into(), remove: false }));
        assert!(validate_outgoing(&r("🔥"), false).is_ok());
        assert!(validate_outgoing(&r(""), false).is_err());
        assert!(validate_outgoing(&r(&"a".repeat(17)), false).is_err());
    }
}
