//! The single string a contact QR code carries: exactly the two values the
//! manual "Add contact" form asks for (routing token + Ed25519 pubkey), so a
//! scan feeds the same `connect_to_peer` call a hex paste does — the QR is
//! just a different input path, not a different trust step (see
//! KeyExchangePayload::verify in code/client/src/packets.rs).
//!
//! Format: `cryptogram:v1:<routing token hex>:<ed25519 pubkey hex>`.
//! The prefix lets the scanner reject unrelated QR codes (URLs, Wi-Fi
//! codes) with a clear message, and the version leaves room to change the
//! payload later without old builds misreading it. No display name is
//! included: names propagate from their owner in the KeyExchange itself.

const PREFIX: &str = "cryptogram:v1:";

/// Hex lengths of the two fields — 16-byte routing token, 32-byte Ed25519
/// key, matching what `connect_to_peer` in src-tauri/src/commands.rs accepts.
const TOKEN_HEX_LEN: usize = 32;
const ED25519_HEX_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCode {
    pub token_hex: String,
    pub ed25519_hex: String,
}

pub fn encode(token_hex: &str, ed25519_hex: &str) -> String {
    format!("{PREFIX}{token_hex}:{ed25519_hex}")
}

pub fn parse(raw: &str) -> Result<ContactCode, String> {
    let rest = raw
        .trim()
        .strip_prefix(PREFIX)
        .ok_or("That QR code isn't a Cryptogram contact code.")?;
    let (token, key) = rest
        .split_once(':')
        .ok_or("That contact code is incomplete.")?;
    if !is_hex_of_len(token, TOKEN_HEX_LEN) {
        return Err("That contact code has an invalid routing token.".into());
    }
    if !is_hex_of_len(key, ED25519_HEX_LEN) {
        return Err("That contact code has an invalid Ed25519 key.".into());
    }
    Ok(ContactCode {
        token_hex: token.to_ascii_lowercase(),
        ed25519_hex: key.to_ascii_lowercase(),
    })
}

fn is_hex_of_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "00112233445566778899aabbccddeeff";
    const KEY: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    #[test]
    fn round_trips() {
        let parsed = parse(&encode(TOKEN, KEY)).unwrap();
        assert_eq!(parsed.token_hex, TOKEN);
        assert_eq!(parsed.ed25519_hex, KEY);
    }

    #[test]
    fn tolerates_surrounding_whitespace_and_uppercase_hex() {
        let raw = format!("  {}\n", encode(&TOKEN.to_uppercase(), &KEY.to_uppercase()));
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.token_hex, TOKEN);
        assert_eq!(parsed.ed25519_hex, KEY);
    }

    #[test]
    fn rejects_other_qr_codes() {
        assert!(parse("https://example.com").is_err());
        assert!(parse(&format!("cryptogram:v2:{TOKEN}:{KEY}")).is_err());
    }

    #[test]
    fn rejects_bad_fields() {
        assert!(parse(&format!("{PREFIX}{TOKEN}")).is_err());
        assert!(parse(&encode(&TOKEN[..30], KEY)).is_err());
        assert!(parse(&encode(TOKEN, &KEY[..62])).is_err());
        assert!(parse(&encode(TOKEN, &KEY.replace('f', "g"))).is_err());
    }
}
