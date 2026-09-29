// Fixed-size padding for chat message plaintexts, applied *inside* the E2E
// encryption so every chat packet on the wire is the same size and neither
// the relay nor a network observer can read a message's length off it.
//
// Every padded block is exactly `PADDED_LEN` bytes:
//
//   [2-byte BE message length | message bytes | zero bytes...]
//
// Zeros rather than random fill: the whole block is encrypted, so the
// padding looks random on the wire either way, and zeros let `unpad`
// reject any block whose tail isn't exactly what `pad` would have written.

use anyhow::{Result, anyhow};

/// Size of every padded chat plaintext. Keeps a chat packet at 1150 bytes on
/// the wire — under the 1232-byte UDP payload that crosses any IPv6 path
/// (and practically any IPv4 one) without IP fragmentation.
pub const PADDED_LEN: usize = 1024;
const LEN_PREFIX: usize = 2;
/// Longest message, in UTF-8 bytes, that fits in one padded block.
pub const MAX_MESSAGE_LEN: usize = PADDED_LEN - LEN_PREFIX;

/// Wraps `message` in a `PADDED_LEN`-byte block, or errors if it's longer
/// than `MAX_MESSAGE_LEN`. The error text is shown to the user as-is.
pub fn pad(message: &[u8]) -> Result<Vec<u8>> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(anyhow!(
            "Message is too long: {} bytes (limit is {MAX_MESSAGE_LEN}). \
             Emoji and non-Latin characters take up to 4 bytes each.",
            message.len()
        ));
    }
    let mut block = Vec::with_capacity(PADDED_LEN);
    block.extend_from_slice(&(message.len() as u16).to_be_bytes());
    block.extend_from_slice(message);
    block.resize(PADDED_LEN, 0);
    Ok(block)
}

/// Inverse of `pad`. Only ever called on an already-authenticated
/// plaintext, so these checks catch a buggy or outdated peer, not an
/// attacker — no need for them to be constant-time.
pub fn unpad(block: &[u8]) -> Result<&[u8]> {
    if block.len() != PADDED_LEN {
        return Err(anyhow!(
            "Padded message must be {PADDED_LEN} bytes, got {}",
            block.len()
        ));
    }
    let len = u16::from_be_bytes([block[0], block[1]]) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(anyhow!("Padded message length prefix is out of range"));
    }
    let (message, padding) = block[LEN_PREFIX..].split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(anyhow!("Padded message has non-zero padding"));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let max = vec![b'x'; MAX_MESSAGE_LEN];
        let cases: [&[u8]; 4] = [b"", b"hi", "héllo 👋".as_bytes(), &max];
        for message in cases {
            let block = pad(message).unwrap();
            assert_eq!(block.len(), PADDED_LEN);
            assert_eq!(unpad(&block).unwrap(), message);
        }
    }

    #[test]
    fn test_pad_rejects_message_over_limit() {
        let err = pad(&vec![b'x'; MAX_MESSAGE_LEN + 1]).unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
    }

    #[test]
    fn test_unpad_rejects_wrong_block_size() {
        assert!(unpad(&[]).is_err());
        assert!(unpad(&vec![0u8; PADDED_LEN - 1]).is_err());
        assert!(unpad(&vec![0u8; PADDED_LEN + 1]).is_err());
        // An unpadded message, as an older client would send it.
        assert!(unpad(b"hello").is_err());
    }

    #[test]
    fn test_unpad_rejects_out_of_range_length_prefix() {
        let mut block = pad(b"hi").unwrap();
        block[..2].copy_from_slice(&((MAX_MESSAGE_LEN + 1) as u16).to_be_bytes());
        assert!(unpad(&block).is_err());
        block[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(unpad(&block).is_err());
    }

    #[test]
    fn test_unpad_rejects_non_zero_padding() {
        let mut block = pad(b"hi").unwrap();
        *block.last_mut().unwrap() = 1;
        assert!(unpad(&block).is_err());

        // A length prefix shorter than the real message leaves message
        // bytes in the padding region, which must be caught the same way.
        let mut block = pad(b"hello").unwrap();
        block[..2].copy_from_slice(&2u16.to_be_bytes());
        assert!(unpad(&block).is_err());
    }
}
