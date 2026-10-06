//! The single string a contact QR code carries: exactly the two values the
//! manual "Add contact" form asks for (routing token + Ed25519 pubkey), so a
//! scan feeds the same `connect_to_peer` call a hex paste does — the QR is
//! just a different input path, not a different trust step (see
//! KeyExchangePayload::verify in code/client/src/packets.rs).
//!
//! Format: `CG2:<Base45 of the 16-byte token then the 32-byte key>`.
//! Base45 (RFC 9285) uses only characters QR's alphanumeric mode encodes
//! compactly, so the code is a 29x29 QR (version 3) rather than the 37x37
//! the old `cryptogram:v1:<hex>:<hex>` text needed: bigger squares at the
//! same size on screen, which a camera further away can still make out.
//! The prefix lets the scanner reject unrelated QR codes (URLs, Wi-Fi
//! codes) with a clear message, and the version leaves room to change the
//! payload later without old builds misreading it. No display name is
//! included: names propagate from their owner in the KeyExchange itself.

const PREFIX: &str = "CG2:";
/// The format before this one, recognised only to say so.
const OLD_PREFIX: &str = "cryptogram:v1:";

/// Byte lengths of the two fields — 16-byte routing token, 32-byte Ed25519
/// key, matching what `connect_to_peer` in src-tauri/src/commands.rs accepts.
const TOKEN_LEN: usize = 16;
const ED25519_LEN: usize = 32;

const BASE45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCode {
    pub token_hex: String,
    pub ed25519_hex: String,
}

pub fn encode(token_hex: &str, ed25519_hex: &str) -> Result<String, String> {
    let mut bytes = hex_decode(token_hex, TOKEN_LEN).ok_or("Invalid routing token.")?;
    bytes.extend(hex_decode(ed25519_hex, ED25519_LEN).ok_or("Invalid Ed25519 key.")?);
    Ok(format!("{PREFIX}{}", base45_encode(&bytes)))
}

pub fn parse(raw: &str) -> Result<ContactCode, String> {
    // Not trimmed: a space is a Base45 digit.
    let Some(rest) = raw.strip_prefix(PREFIX) else {
        return Err(if raw.trim_start().starts_with(OLD_PREFIX) {
            "That contact code is from an older version of the app. Both of you need the latest one."
        } else {
            "That QR code isn't a Cryptogram contact code."
        }
        .into());
    };
    let bytes = base45_decode(rest)
        .filter(|b| b.len() == TOKEN_LEN + ED25519_LEN)
        .ok_or("That contact code is damaged or incomplete.")?;
    let (token, key) = bytes.split_at(TOKEN_LEN);
    Ok(ContactCode {
        token_hex: hex_encode(token),
        ed25519_hex: hex_encode(key),
    })
}

/// RFC 9285: each 2 bytes become 3 digits (least significant first), and
/// a final odd byte becomes 2.
fn base45_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(2) * 3);
    for chunk in bytes.chunks(2) {
        let (mut n, digits) = match *chunk {
            [a, b] => (usize::from(a) << 8 | usize::from(b), 3),
            [a] => (usize::from(a), 2),
            _ => unreachable!("chunks(2) yields 1 or 2 bytes"),
        };
        for _ in 0..digits {
            out.push(char::from(BASE45[n % 45]));
            n /= 45;
        }
    }
    out
}

fn base45_decode(text: &str) -> Option<Vec<u8>> {
    let digits = text
        .bytes()
        .map(|c| BASE45.iter().position(|&d| d == c))
        .collect::<Option<Vec<_>>>()?;
    let mut out = Vec::with_capacity(digits.len() / 3 * 2 + 1);
    for group in digits.chunks(3) {
        let n = group.iter().rev().fold(0, |n, &d| n * 45 + d);
        match group.len() {
            3 => out.extend(u16::try_from(n).ok()?.to_be_bytes()),
            2 => out.push(u8::try_from(n).ok()?),
            _ => return None,
        }
    }
    Some(out)
}

fn hex_decode(hex: &str, len: usize) -> Option<Vec<u8>> {
    if hex.len() != len * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..len)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "00112233445566778899aabbccddeeff";
    const KEY: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    #[test]
    fn round_trips() {
        let code = encode(TOKEN, KEY).unwrap();
        assert_eq!(code.len(), PREFIX.len() + 72);
        let parsed = parse(&code).unwrap();
        assert_eq!(parsed.token_hex, TOKEN);
        assert_eq!(parsed.ed25519_hex, KEY);
    }

    #[test]
    fn accepts_uppercase_hex_to_encode() {
        let code = encode(&TOKEN.to_uppercase(), &KEY.to_uppercase()).unwrap();
        assert_eq!(code, encode(TOKEN, KEY).unwrap());
    }

    #[test]
    fn base45_matches_rfc_9285_examples() {
        for (bytes, text) in [
            (&b"AB"[..], "BB8"),
            (b"Hello!!", "%69 VD92EX0"),
            (b"base-45", "UJCLQE7W581"),
            (b"ietf!", "QED8WEX0"),
        ] {
            assert_eq!(base45_encode(bytes), text);
            assert_eq!(base45_decode(text).as_deref(), Some(bytes));
        }
        assert!(
            base45_decode("GGW").is_none(),
            "65536 doesn't fit two bytes"
        );
        assert!(base45_decode("A").is_none(), "a lone digit is never valid");
        assert!(base45_decode("ab").is_none(), "lowercase isn't Base45");
    }

    #[test]
    fn rejects_other_qr_codes() {
        assert!(parse("https://example.com").is_err());
        assert!(parse("CG3:BB8").is_err());
    }

    #[test]
    fn says_when_a_code_is_from_an_older_version() {
        let err = parse(&format!("cryptogram:v1:{TOKEN}:{KEY}")).unwrap_err();
        assert!(err.contains("older version"), "{err}");
    }

    #[test]
    fn rejects_damaged_codes() {
        let code = encode(TOKEN, KEY).unwrap();
        assert!(parse(&code[..code.len() - 3]).is_err(), "too short");
        assert!(parse(&format!("{code}BB8")).is_err(), "too long");
        let lowercase = format!("{}a", &code[..code.len() - 1]);
        assert!(parse(&lowercase).is_err(), "not Base45");
    }

    #[test]
    fn rejects_bad_hex_to_encode() {
        assert!(encode(&TOKEN[..30], KEY).is_err());
        assert!(encode(TOKEN, &KEY.replace('f', "g")).is_err());
        assert!(encode(&format!("+{}", &TOKEN[1..]), KEY).is_err());
    }
}
