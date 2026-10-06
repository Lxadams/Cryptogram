//! The link between a client and the relay, shared by both ends.
//!
//! Everything either side sends is a **cell**: exactly `CELL_LEN` bytes,
//! carried as one QUIC datagram (RFC 9221). Each side sends cells at a
//! constant average rate (`pace::CELLS_PER_SECOND`, Poisson-spaced) whether
//! or not it has anything to say; an idle cell is all padding. With QUIC
//! padding every packet to the same size (`quic::transport_config`), an
//! observer sees one packet size at one rate, whatever the users are doing.
//!
//! - `format`: the cell layout (header with a sequence number and a receipt
//!   for the other side's cells, then frames, then padding).
//! - `window`: receipt bookkeeping, i.e. which cells arrived, which were
//!   lost, and a running estimate of the loss rate.
//! - `pace`: the Poisson clock cells are sent on.
//! - `proof`: the hello that opens a link, proving the client has the app's
//!   access key and owns its routing token.
//! - `quic`: the QUIC settings both ends use, and `CellTransport`, the
//!   "send a cell / receive a cell" interface the rest of the code is
//!   written against, so a mixnet can replace QUIC later.

pub mod format;
pub mod pace;
pub mod proof;
pub mod quic;
pub mod window;

pub use format::{CELL_LEN, CellBuilder, CellError, Frame, ParsedCell, Receipt, parse};
pub use quic::CellTransport;
pub use window::{LossEstimate, ReceiveWindow, Resolved, SendWindow};

/// A user's 16-byte routing token: what the relay routes by.
pub type RoutingToken = [u8; 16];
