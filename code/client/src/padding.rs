// Fixed-size padding for chat plaintexts, applied *inside* the E2E
// encryption so every chat packet on the wire is the same size and neither
// the relay nor a network observer can read a message's length off it. What
// gets padded is one chunk of a message (see `chunks`), never more.
//
// Every padded block is exactly `PADDED_LEN` bytes:
//
//   [2-byte BE payload length | payload bytes | zero bytes...]
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
/// Longest payload that fits in one padded block.
pub const MAX_PAYLOAD_LEN: usize = PADDED_LEN - LEN_PREFIX;

/// Wraps `payload` in a `PADDED_LEN`-byte block, or errors if it's longer
/// than `MAX_PAYLOAD_LEN`.
pub fn pad(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "Payload of {} bytes doesn't fit a padded block (limit is {MAX_PAYLOAD_LEN})",
            payload.len()
        ));
    }
    let mut block = Vec::with_capacity(PADDED_LEN);
    block.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    block.extend_from_slice(payload);
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
    if len > MAX_PAYLOAD_LEN {
        return Err(anyhow!("Padded message length prefix is out of range"));
    }
    let (payload, padding) = block[LEN_PREFIX..].split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(anyhow!("Padded message has non-zero padding"));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let max = vec![b'x'; MAX_PAYLOAD_LEN];
        let cases: [&[u8]; 4] = [b"", b"hi", "héllo 👋".as_bytes(), &max];
        for payload in cases {
            let block = pad(payload).unwrap();
            assert_eq!(block.len(), PADDED_LEN);
            assert_eq!(unpad(&block).unwrap(), payload);
        }
    }

    #[test]
    fn test_pad_rejects_payload_over_limit() {
        assert!(pad(&vec![b'x'; MAX_PAYLOAD_LEN + 1]).is_err());
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
        block[..2].copy_from_slice(&((MAX_PAYLOAD_LEN + 1) as u16).to_be_bytes());
        assert!(unpad(&block).is_err());
        block[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(unpad(&block).is_err());
    }

    #[test]
    fn test_unpad_rejects_non_zero_padding() {
        let mut block = pad(b"hi").unwrap();
        *block.last_mut().unwrap() = 1;
        assert!(unpad(&block).is_err());

        // A length prefix shorter than the real payload leaves payload
        // bytes in the padding region, which must be caught the same way.
        let mut block = pad(b"hello").unwrap();
        block[..2].copy_from_slice(&2u16.to_be_bytes());
        assert!(unpad(&block).is_err());
    }
}
