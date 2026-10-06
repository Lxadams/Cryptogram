//! Cell layout. Every cell is exactly `CELL_LEN` bytes:
//!
//! ```text
//! [4 seq][4 receipt largest][8 receipt bitmap]  header (big-endian)
//! ([1 type][2 len][len bytes])*                 frames
//! [0x00 ...]                                     padding to CELL_LEN
//! ```
//!
//! `seq` numbers this side's cells on this link, from 1. The receipt says
//! which of the *other* side's cells arrived (see `Receipt`), so every cell
//! doubles as a batched acknowledgement. A frame type of 0 ends the frames;
//! unknown frame types are skipped, so either end can add one later.
//!
//! QUIC encrypts the whole cell, so nobody on the path sees any of this,
//! including how much of a cell is padding.

use crate::RoutingToken;
use crate::proof::HELLO_LEN;
use std::fmt;

/// Size of every cell. A QUIC packet of `quic::MTU` (1200) bytes fits a
/// datagram of up to 1162 bytes with quinn's 8-byte connection IDs; this
/// leaves a little headroom under that.
pub const CELL_LEN: usize = 1150;

const HEADER_LEN: usize = 4 + 4 + 8;
const FRAME_HEADER_LEN: usize = 1 + 2;

/// Largest payload a `Deliver` frame can carry (one per cell).
pub const MAX_DELIVER_PAYLOAD: usize = CELL_LEN - HEADER_LEN - FRAME_HEADER_LEN;
/// Largest payload a `Forward` frame can carry (one per cell).
pub const MAX_FORWARD_PAYLOAD: usize = MAX_DELIVER_PAYLOAD - 16;

const TYPE_END: u8 = 0;
const TYPE_HELLO: u8 = 1;
const TYPE_FORWARD: u8 = 2;
const TYPE_DELIVER: u8 = 3;

/// Which of the other side's cells have arrived: the highest sequence
/// number seen (0 if none yet), and a bitmap of the 64 before it. Bit `i`
/// set means cell `largest - 1 - i` arrived.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Receipt {
    pub largest: u32,
    pub bitmap: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Client to relay, until the relay starts answering: opens the link
    /// (see `proof`).
    Hello(&'a [u8; HELLO_LEN]),
    /// Client to relay: pass `payload` on to whoever owns routing token `to`.
    Forward { to: RoutingToken, payload: &'a [u8] },
    /// Relay to client: a payload someone sent us.
    Deliver(&'a [u8]),
}

impl Frame<'_> {
    fn kind(&self) -> u8 {
        match self {
            Frame::Hello(_) => TYPE_HELLO,
            Frame::Forward { .. } => TYPE_FORWARD,
            Frame::Deliver(_) => TYPE_DELIVER,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            Frame::Hello(body) => body.len(),
            Frame::Forward { payload, .. } => 16 + payload.len(),
            Frame::Deliver(payload) => payload.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellError {
    /// Not `CELL_LEN` bytes: not one of ours.
    WrongLength,
    /// A frame runs past the end of the cell, or is the wrong size for its type.
    BadFrame,
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CellError::WrongLength => "cell is not CELL_LEN bytes",
            CellError::BadFrame => "malformed frame in cell",
        })
    }
}

impl std::error::Error for CellError {}

/// Builds one cell: header first, then frames while they fit, then padding.
pub struct CellBuilder {
    buf: Vec<u8>,
}

impl CellBuilder {
    pub fn new(seq: u32, receipt: Receipt) -> Self {
        let mut buf = Vec::with_capacity(CELL_LEN);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&receipt.largest.to_be_bytes());
        buf.extend_from_slice(&receipt.bitmap.to_be_bytes());
        Self { buf }
    }

    /// Whether `frame` fits in what's left of the cell.
    pub fn fits(&self, frame: &Frame) -> bool {
        self.buf.len() + FRAME_HEADER_LEN + frame.body_len() <= CELL_LEN
    }

    /// Append `frame`, or return `false` (leaving the cell as it was) if it
    /// doesn't fit.
    pub fn push(&mut self, frame: &Frame) -> bool {
        if !self.fits(frame) {
            return false;
        }
        self.buf.push(frame.kind());
        self.buf
            .extend_from_slice(&(frame.body_len() as u16).to_be_bytes());
        match frame {
            Frame::Hello(body) => self.buf.extend_from_slice(&body[..]),
            Frame::Forward { to, payload } => {
                self.buf.extend_from_slice(to);
                self.buf.extend_from_slice(payload);
            }
            Frame::Deliver(payload) => self.buf.extend_from_slice(payload),
        }
        true
    }

    /// The finished cell, zero-padded to `CELL_LEN`.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.resize(CELL_LEN, TYPE_END);
        self.buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCell<'a> {
    pub seq: u32,
    pub receipt: Receipt,
    pub frames: Vec<Frame<'a>>,
}

/// Read a cell. Anything that isn't exactly `CELL_LEN` bytes, or whose
/// frames don't add up, is an error, never a panic.
pub fn parse(cell: &[u8]) -> Result<ParsedCell<'_>, CellError> {
    if cell.len() != CELL_LEN {
        return Err(CellError::WrongLength);
    }
    let u32_at = |i: usize| u32::from_be_bytes(cell[i..i + 4].try_into().unwrap());
    let seq = u32_at(0);
    let receipt = Receipt {
        largest: u32_at(4),
        bitmap: u64::from_be_bytes(cell[8..16].try_into().unwrap()),
    };
    let mut frames = Vec::new();
    let mut rest = &cell[HEADER_LEN..];
    while let Some((&kind, after_kind)) = rest.split_first() {
        if kind == TYPE_END {
            break;
        }
        let Some((len, body_and_rest)) = after_kind.split_first_chunk::<2>() else {
            return Err(CellError::BadFrame);
        };
        let len = u16::from_be_bytes(*len) as usize;
        if body_and_rest.len() < len {
            return Err(CellError::BadFrame);
        }
        let (body, after) = body_and_rest.split_at(len);
        rest = after;
        frames.push(match kind {
            TYPE_HELLO => Frame::Hello(body.try_into().map_err(|_| CellError::BadFrame)?),
            TYPE_FORWARD => {
                let Some((to, payload)) = body.split_first_chunk::<16>() else {
                    return Err(CellError::BadFrame);
                };
                Frame::Forward { to: *to, payload }
            }
            TYPE_DELIVER => Frame::Deliver(body),
            _ => continue,
        });
    }
    Ok(ParsedCell {
        seq,
        receipt,
        frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_every_frame_type() {
        let receipt = Receipt {
            largest: 41,
            bitmap: 0xF0F0,
        };
        let hello = [7u8; HELLO_LEN];
        let mut cell = CellBuilder::new(42, receipt);
        assert!(cell.push(&Frame::Hello(&hello)));
        assert!(cell.push(&Frame::Forward {
            to: [9; 16],
            payload: b"to someone",
        }));
        assert!(cell.push(&Frame::Deliver(b"from someone")));
        let cell = cell.finish();
        assert_eq!(cell.len(), CELL_LEN);

        let parsed = parse(&cell).unwrap();
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.receipt, receipt);
        assert_eq!(
            parsed.frames,
            [
                Frame::Hello(&hello),
                Frame::Forward {
                    to: [9; 16],
                    payload: b"to someone"
                },
                Frame::Deliver(b"from someone"),
            ]
        );
    }

    #[test]
    fn an_idle_cell_is_just_a_header_and_padding() {
        let cell = CellBuilder::new(1, Receipt::default()).finish();
        assert_eq!(cell.len(), CELL_LEN);
        assert!(cell[4..].iter().all(|&b| b == 0));
        assert!(parse(&cell).unwrap().frames.is_empty());
    }

    /// The largest payloads the transport sends fit one per cell: a sealed
    /// FEC symbol is 1,093 bytes (see code/client/src/transport.rs).
    #[test]
    fn a_full_size_payload_fits_and_one_byte_more_does_not() {
        let mut cell = CellBuilder::new(1, Receipt::default());
        let big = vec![1u8; MAX_FORWARD_PAYLOAD];
        const { assert!(MAX_FORWARD_PAYLOAD >= 1093) };
        assert!(cell.push(&Frame::Forward {
            to: [0; 16],
            payload: &big,
        }));
        assert!(!cell.push(&Frame::Deliver(b"x")), "full");

        let mut cell = CellBuilder::new(1, Receipt::default());
        let too_big = vec![1u8; MAX_FORWARD_PAYLOAD + 1];
        assert!(!cell.push(&Frame::Forward {
            to: [0; 16],
            payload: &too_big,
        }));
        assert!(cell.push(&Frame::Deliver(&vec![2u8; MAX_DELIVER_PAYLOAD])));
    }

    #[test]
    fn malformed_cells_are_errors_not_panics() {
        assert_eq!(parse(&[0u8; 10]), Err(CellError::WrongLength));
        assert_eq!(parse(&vec![0u8; CELL_LEN + 1]), Err(CellError::WrongLength));

        let mut cell = CellBuilder::new(1, Receipt::default()).finish();
        // A frame claiming to run past the end of the cell.
        cell[16] = TYPE_DELIVER;
        cell[17..19].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse(&cell), Err(CellError::BadFrame));
        // A hello of the wrong size.
        cell[16] = TYPE_HELLO;
        cell[17..19].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(parse(&cell), Err(CellError::BadFrame));
        // A forward too short to hold its token.
        cell[16] = TYPE_FORWARD;
        assert_eq!(parse(&cell), Err(CellError::BadFrame));
        // A frame header cut off by the end of the cell.
        let mut cell = CellBuilder::new(1, Receipt::default());
        assert!(cell.push(&Frame::Deliver(&vec![1; MAX_DELIVER_PAYLOAD - 2])));
        let mut cell = cell.finish();
        cell[CELL_LEN - 2] = TYPE_DELIVER;
        assert_eq!(parse(&cell), Err(CellError::BadFrame));
    }

    #[test]
    fn unknown_frame_types_are_skipped() {
        let mut cell = CellBuilder::new(1, Receipt::default());
        cell.push(&Frame::Deliver(b"before"));
        let mut cell = cell.finish();
        let at = 16 + 3 + 6;
        cell[at] = 0x7F;
        cell[at + 1..at + 3].copy_from_slice(&2u16.to_be_bytes());
        cell[at + 5] = TYPE_DELIVER;
        cell[at + 6..at + 8].copy_from_slice(&1u16.to_be_bytes());
        cell[at + 8] = b'!';
        assert_eq!(
            parse(&cell).unwrap().frames,
            [Frame::Deliver(b"before"), Frame::Deliver(b"!")]
        );
    }
}
