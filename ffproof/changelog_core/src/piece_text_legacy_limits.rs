//! Legacy PieceText sizing constants kept for cleanup/prover fixtures.
//!
//! `PieceTextEditOp` no longer enforces these as document-level edit caps. They
//! remain available for code that needs a conservative historical row-count
//! bound, such as cleanup cycle guards and legacy proof-size tests.

/// Historical all-row PieceText document count used by cleanup/prover code.
pub const MAX_PIECETEXT_PIECES_PER_DOCUMENT: usize = 16_384;

/// Historical live-row PieceText document count retained for compatibility.
pub const MAX_PIECETEXT_LIVE_PIECES_PER_DOCUMENT: usize = 4_096;
