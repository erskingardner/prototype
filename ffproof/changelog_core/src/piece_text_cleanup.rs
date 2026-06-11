use crate::changelog::{
    ChangelogEntry, ChangelogError, KvData, LogMessage, OpType, ROOT_TREE_PATH,
};
use crate::piece_text::PieceTextAddress;
use encrypted_spaces_storage_encoding::keys::{
    parse_key, piece_text_cleanup_buffers_key, piece_text_cleanup_pieces_key, ParsedKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1: u8 = 1;

/// Maximum number of `_piecetext_pieces` rows removed by one
/// `PieceTextCleanupPieces` envelope (summed across all runs).
pub const MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS: usize = 256;

/// Maximum number of splice runs in one `PieceTextCleanupPieces` envelope.
/// Capped independently of removed rows so boundary reads stay bounded even
/// when every run removes only a single row.
pub const MAX_PIECE_TEXT_CLEANUP_RUNS: usize = 64;

/// Maximum number of `_piecetext_buffers` rows deleted by one `PieceTextCleanupBuffers`
/// envelope. Reduced from 256 after the 256-buffer empty-range and full-op
/// proof measurements exceeded the 128 KiB per-change cleanup budget.
pub const MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS: usize = 64;

/// One local linked-list splice: a contiguous chain-ordered run of tombstoned
/// `_piecetext_pieces` rows to remove.
///
/// The bracketing survivors are NOT carried on the wire — the verifier derives
/// them from the authenticated endpoint rows (`removals.first().prev_id` and
/// `removals.last().next_id`). A derived survivor of `0` means the run starts at
/// the list head (resp. ends at the tail). The verifier authenticates the local
/// links, derives the survivors, runs the cross-run independence checks on those
/// derived values, and re-derives the relink writes — without reading the
/// survivor rows (their consistency follows from the doubly-linked-list
/// invariant every prior op maintains).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceTextCleanupRunV1 {
    /// Tombstoned rows to remove, in forward chain order.
    pub removals: Vec<i64>,
}

/// System-source piece-cleanup manifest for one PieceText document.
///
/// Trust model: this envelope is carried by unsigned
/// `OpType::PieceTextCleanupPieces` entries. The server is the sole intended
/// producer, and the verifier re-derives every delete/relink from authenticated
/// tree state before accepting it. A piece cleanup must address an authenticated
/// parent `(table, row_id, column, list_number)`, remove only already-
/// tombstoned `_piecetext_pieces` rows via local splices, set `op_id` to the current
/// change id, and never touch `_piecetext_buffers`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceTextCleanupPiecesEnvelopeV1 {
    pub version: u8,
    pub address: PieceTextAddress,
    pub list_number: i64,
    pub op_id: i64,
    pub runs: Vec<PieceTextCleanupRunV1>,
}

impl PieceTextCleanupPiecesEnvelopeV1 {
    /// Validate the structural (tree-independent) shape of the envelope.
    ///
    /// This enforces the parts of the V1 disjoint-splice predicate that follow
    /// purely from the envelope bytes: bounds, per-run non-emptiness, global
    /// removal dedup, and canonical run ordering by first removed row id. The
    /// bracketing survivors are not on the wire — they are derived from
    /// authenticated rows — so the cross-run independence checks (no shared
    /// survivor, no survivor that is also a removed row) and all other tree-bound
    /// checks (rows exist, are tombstoned, local links match, derived write-key
    /// disjointness) are applied by the op verifier.
    pub fn validate_shape(&self) -> Result<(), ChangelogError> {
        if self.version != PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1 {
            return Err(ChangelogError::Generic(format!(
                "unsupported PieceTextCleanupPiecesEnvelopeV1 version {}",
                self.version
            )));
        }
        self.address.validate()?;
        if self.list_number <= 0 {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupPiecesEnvelopeV1.list_number must be greater than 0".to_string(),
            ));
        }
        if self.op_id <= 0 {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupPiecesEnvelopeV1.op_id must be greater than 0".to_string(),
            ));
        }
        validate_runs(&self.runs)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChangelogError> {
        postcard::to_allocvec(self).map_err(|e| {
            ChangelogError::Generic(format!(
                "failed to serialize PieceTextCleanupPiecesEnvelopeV1: {e}"
            ))
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChangelogError> {
        let (envelope, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|e| {
                ChangelogError::Generic(format!(
                    "failed to decode PieceTextCleanupPiecesEnvelopeV1: {e}"
                ))
            })?;
        if !trailing.is_empty() {
            return Err(ChangelogError::Generic(format!(
                "PieceTextCleanupPiecesEnvelopeV1 has {} trailing bytes",
                trailing.len()
            )));
        }
        let canonical = envelope.canonical_bytes()?;
        if canonical != bytes {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupPiecesEnvelopeV1 bytes are not canonical".to_string(),
            ));
        }
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_entry_key(&self, key: &[u8]) -> Result<(), ChangelogError> {
        match parse_key(key) {
            Ok(ParsedKey::PieceTextCleanupPieces {
                table,
                row_id,
                column,
                op_id,
            }) if table == self.address.table
                && row_id == self.address.row_id
                && column == self.address.column
                && op_id == self.op_id =>
            {
                Ok(())
            }
            Ok(ParsedKey::PieceTextCleanupPieces { .. }) => Err(ChangelogError::KeyMismatch(
                "piece-text piece-cleanup entry key does not match envelope address/op_id"
                    .to_string(),
            )),
            Ok(other) => Err(ChangelogError::KeyMismatch(format!(
                "piece-text piece-cleanup entry key must use PTCP tag, got {other:?}"
            ))),
            Err(e) => Err(ChangelogError::KeyMismatch(format!(
                "failed to parse piece-text piece-cleanup entry key: {e}"
            ))),
        }
    }

    pub fn decode_from_entry(entry: &ChangelogEntry) -> Result<Self, ChangelogError> {
        if entry.message.op_type != OpType::PieceTextCleanupPieces {
            return Err(ChangelogError::Generic(format!(
                "expected OpType::PieceTextCleanupPieces, got {:?}",
                entry.message.op_type
            )));
        }
        if entry.message.tree_path != ROOT_TREE_PATH {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupPieces tree_path must be /".to_string(),
            ));
        }
        if entry.message.entries.len() != 1 {
            return Err(ChangelogError::Generic(format!(
                "PieceTextCleanupPieces must carry exactly one manifest entry, got {}",
                entry.message.entries.len()
            )));
        }
        let kv = &entry.message.entries[0];
        let envelope = Self::from_canonical_bytes(&kv.value)?;
        envelope.validate_entry_key(&kv.key)?;
        Ok(envelope)
    }

    pub fn changelog_entry_kv(&self) -> Result<KvData, ChangelogError> {
        Ok(KvData {
            key: piece_text_cleanup_pieces_key(
                &self.address.table,
                self.address.row_id,
                &self.address.column,
                self.op_id,
            ),
            value: self.canonical_bytes()?,
        })
    }

    pub fn changelog_message(&self) -> Result<LogMessage, ChangelogError> {
        Ok(LogMessage {
            op_type: OpType::PieceTextCleanupPieces,
            tree_path: ROOT_TREE_PATH.to_vec(),
            entries: vec![self.changelog_entry_kv()?],
        })
    }
}

/// System-source buffer-cleanup manifest for one PieceText document.
///
/// Trust model: this envelope is carried by unsigned
/// `OpType::PieceTextCleanupBuffers` entries. It physically deletes `_piecetext_buffers`
/// rows only after piece cleanup has already removed every
/// `_piecetext_pieces.buffer_id` index reference to them. The verifier proves that
/// index range is empty (a pre-state check), validates `_piecetext_buffers` owner
/// metadata against the envelope address, and sets `op_id` to the current change
/// id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceTextCleanupBuffersEnvelopeV1 {
    pub version: u8,
    pub address: PieceTextAddress,
    pub op_id: i64,
    /// `_piecetext_buffers` row ids. Must be sorted ascending and unique.
    pub buffer_removals: Vec<i64>,
}

impl PieceTextCleanupBuffersEnvelopeV1 {
    pub fn validate_shape(&self) -> Result<(), ChangelogError> {
        if self.version != PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1 {
            return Err(ChangelogError::Generic(format!(
                "unsupported PieceTextCleanupBuffersEnvelopeV1 version {}",
                self.version
            )));
        }
        self.address.validate()?;
        if self.op_id <= 0 {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupBuffersEnvelopeV1.op_id must be greater than 0".to_string(),
            ));
        }
        if self.buffer_removals.is_empty() {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupBuffersEnvelopeV1 must remove at least one buffer".to_string(),
            ));
        }
        validate_strictly_ascending_positive(
            "buffer_removals",
            &self.buffer_removals,
            MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChangelogError> {
        postcard::to_allocvec(self).map_err(|e| {
            ChangelogError::Generic(format!(
                "failed to serialize PieceTextCleanupBuffersEnvelopeV1: {e}"
            ))
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChangelogError> {
        let (envelope, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|e| {
                ChangelogError::Generic(format!(
                    "failed to decode PieceTextCleanupBuffersEnvelopeV1: {e}"
                ))
            })?;
        if !trailing.is_empty() {
            return Err(ChangelogError::Generic(format!(
                "PieceTextCleanupBuffersEnvelopeV1 has {} trailing bytes",
                trailing.len()
            )));
        }
        let canonical = envelope.canonical_bytes()?;
        if canonical != bytes {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupBuffersEnvelopeV1 bytes are not canonical".to_string(),
            ));
        }
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn validate_entry_key(&self, key: &[u8]) -> Result<(), ChangelogError> {
        match parse_key(key) {
            Ok(ParsedKey::PieceTextCleanupBuffers {
                table,
                row_id,
                column,
                op_id,
            }) if table == self.address.table
                && row_id == self.address.row_id
                && column == self.address.column
                && op_id == self.op_id =>
            {
                Ok(())
            }
            Ok(ParsedKey::PieceTextCleanupBuffers { .. }) => Err(ChangelogError::KeyMismatch(
                "piece-text buffer-cleanup entry key does not match envelope address/op_id"
                    .to_string(),
            )),
            Ok(other) => Err(ChangelogError::KeyMismatch(format!(
                "piece-text buffer-cleanup entry key must use PTCB tag, got {other:?}"
            ))),
            Err(e) => Err(ChangelogError::KeyMismatch(format!(
                "failed to parse piece-text buffer-cleanup entry key: {e}"
            ))),
        }
    }

    pub fn decode_from_entry(entry: &ChangelogEntry) -> Result<Self, ChangelogError> {
        if entry.message.op_type != OpType::PieceTextCleanupBuffers {
            return Err(ChangelogError::Generic(format!(
                "expected OpType::PieceTextCleanupBuffers, got {:?}",
                entry.message.op_type
            )));
        }
        if entry.message.tree_path != ROOT_TREE_PATH {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupBuffers tree_path must be /".to_string(),
            ));
        }
        if entry.message.entries.len() != 1 {
            return Err(ChangelogError::Generic(format!(
                "PieceTextCleanupBuffers must carry exactly one manifest entry, got {}",
                entry.message.entries.len()
            )));
        }
        let kv = &entry.message.entries[0];
        let envelope = Self::from_canonical_bytes(&kv.value)?;
        envelope.validate_entry_key(&kv.key)?;
        Ok(envelope)
    }

    pub fn changelog_entry_kv(&self) -> Result<KvData, ChangelogError> {
        Ok(KvData {
            key: piece_text_cleanup_buffers_key(
                &self.address.table,
                self.address.row_id,
                &self.address.column,
                self.op_id,
            ),
            value: self.canonical_bytes()?,
        })
    }

    pub fn changelog_message(&self) -> Result<LogMessage, ChangelogError> {
        Ok(LogMessage {
            op_type: OpType::PieceTextCleanupBuffers,
            tree_path: ROOT_TREE_PATH.to_vec(),
            entries: vec![self.changelog_entry_kv()?],
        })
    }
}

/// Enforce the structural part of the V1 disjoint-splice predicate over an
/// envelope's runs. Tree-independent — the op verifier adds the tree-bound
/// checks on top.
fn validate_runs(runs: &[PieceTextCleanupRunV1]) -> Result<(), ChangelogError> {
    if runs.is_empty() {
        return Err(ChangelogError::Generic(
            "PieceTextCleanupPiecesEnvelopeV1 must have at least one run".to_string(),
        ));
    }
    if runs.len() > MAX_PIECE_TEXT_CLEANUP_RUNS {
        return Err(ChangelogError::Generic(format!(
            "PieceTextCleanupPiecesEnvelopeV1 has {} runs, exceeding cap {MAX_PIECE_TEXT_CLEANUP_RUNS}",
            runs.len()
        )));
    }

    // Tree-free structural checks only. The bracketing survivors are derived
    // from authenticated rows in the op verifier, so the cross-run independence
    // checks (no shared survivor, no survivor that is also a removed row,
    // prev != next) are tree-bound and live there. Here we enforce: non-empty
    // runs and removals, positive + envelope-wide-unique removal ids, the caps,
    // and a canonical order by first-removed row id (unique per run after dedup,
    // so it is a strict total order — and the sole canonical encoding, since the
    // verifier's "survivor is not a removed row" check forbids splitting a
    // contiguous run into separately-ordered pieces).
    let mut total_removals = 0usize;
    let mut seen_removals: BTreeSet<i64> = BTreeSet::new();
    let mut prev_first_removed: Option<i64> = None;

    for run in runs {
        if run.removals.is_empty() {
            return Err(ChangelogError::Generic(
                "PieceTextCleanupRunV1 must have at least one removal".to_string(),
            ));
        }
        for &rid in &run.removals {
            if rid <= 0 {
                return Err(ChangelogError::Generic(format!(
                    "PieceTextCleanupRunV1 removal row ids must be positive, got {rid}"
                )));
            }
            if !seen_removals.insert(rid) {
                return Err(ChangelogError::Generic(format!(
                    "PieceTextCleanupPiecesEnvelopeV1 removal row id {rid} appears more than once"
                )));
            }
        }
        total_removals += run.removals.len();

        let first_removed = run.removals[0];
        if let Some(prev) = prev_first_removed {
            if first_removed <= prev {
                return Err(ChangelogError::Generic(
                    "PieceTextCleanupPiecesEnvelopeV1 runs must be in ascending order by \
                     first removed row id"
                        .to_string(),
                ));
            }
        }
        prev_first_removed = Some(first_removed);
    }

    if total_removals > MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS {
        return Err(ChangelogError::Generic(format!(
            "PieceTextCleanupPiecesEnvelopeV1 removes {total_removals} rows, exceeding cap \
             {MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS}"
        )));
    }

    Ok(())
}

fn validate_strictly_ascending_positive(
    field: &str,
    ids: &[i64],
    cap: usize,
) -> Result<(), ChangelogError> {
    if ids.len() > cap {
        return Err(ChangelogError::Generic(format!(
            "PieceTextCleanupBuffersEnvelopeV1.{field} has {} entries, exceeding cap {cap}",
            ids.len()
        )));
    }
    let mut prev = None;
    for id in ids {
        if *id <= 0 {
            return Err(ChangelogError::Generic(format!(
                "PieceTextCleanupBuffersEnvelopeV1.{field} row ids must be positive, got {id}"
            )));
        }
        if let Some(prev) = prev {
            if *id <= prev {
                return Err(ChangelogError::Generic(format!(
                    "PieceTextCleanupBuffersEnvelopeV1.{field} must be strictly ascending"
                )));
            }
        }
        prev = Some(*id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::ChangelogEntry;
    use crate::piece_text::PieceTextEditEnvelopeV1;
    use encrypted_spaces_storage_encoding::keys::piece_text_edit_key;

    fn address() -> PieceTextAddress {
        PieceTextAddress {
            table: "channels".to_string(),
            row_id: 42,
            column: "notes_pieces".to_string(),
        }
    }

    fn pieces_envelope() -> PieceTextCleanupPiecesEnvelopeV1 {
        PieceTextCleanupPiecesEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address: address(),
            list_number: 7,
            op_id: 99,
            runs: vec![
                PieceTextCleanupRunV1 {
                    removals: vec![10, 11],
                },
                PieceTextCleanupRunV1 { removals: vec![21] },
            ],
        }
    }

    fn buffers_envelope() -> PieceTextCleanupBuffersEnvelopeV1 {
        PieceTextCleanupBuffersEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address: address(),
            op_id: 99,
            buffer_removals: vec![30, 40],
        }
    }

    fn pieces_entry(envelope: &PieceTextCleanupPiecesEnvelopeV1) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 0,
            parent_change: 0,
            message: envelope.changelog_message().unwrap(),
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn buffers_entry(envelope: &PieceTextCleanupBuffersEnvelopeV1) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 0,
            parent_change: 0,
            message: envelope.changelog_message().unwrap(),
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn piece_text_cleanup_pieces_envelope_roundtrip() {
        let env = pieces_envelope();
        let bytes = env.canonical_bytes().unwrap();
        let decoded = PieceTextCleanupPiecesEnvelopeV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, env);

        let entry = pieces_entry(&env);
        assert_eq!(
            PieceTextCleanupPiecesEnvelopeV1::decode_from_entry(&entry).unwrap(),
            env
        );
    }

    #[test]
    fn piece_text_cleanup_buffers_envelope_roundtrip() {
        let env = buffers_envelope();
        let bytes = env.canonical_bytes().unwrap();
        let decoded = PieceTextCleanupBuffersEnvelopeV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, env);

        let entry = buffers_entry(&env);
        assert_eq!(
            PieceTextCleanupBuffersEnvelopeV1::decode_from_entry(&entry).unwrap(),
            env
        );
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_non_canonical_bytes() {
        let env = pieces_envelope();
        let mut bytes = env.canonical_bytes().unwrap();
        bytes.push(0xFF); // trailing byte → not canonical
        assert!(
            PieceTextCleanupPiecesEnvelopeV1::from_canonical_bytes(&bytes)
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn piece_text_cleanup_buffers_rejects_non_canonical_bytes() {
        let env = buffers_envelope();
        let mut bytes = env.canonical_bytes().unwrap();
        bytes.push(0xFF);
        assert!(
            PieceTextCleanupBuffersEnvelopeV1::from_canonical_bytes(&bytes)
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn piece_text_cleanup_pieces_empty_runs_rejected() {
        let mut env = pieces_envelope();
        env.runs.clear();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("at least one run"));
    }

    #[test]
    fn piece_text_cleanup_pieces_empty_run_removals_rejected() {
        let mut env = pieces_envelope();
        env.runs[0].removals.clear();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("at least one removal"));
    }

    #[test]
    fn piece_text_cleanup_pieces_duplicate_removal_across_runs_rejected() {
        let mut env = pieces_envelope();
        // Reuse row id 10 (already in run 0) in run 1.
        env.runs[1].removals = vec![10];
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("appears more than once"));
    }

    // The shared-boundary, boundary-in-removals, and prev-equals-next checks are
    // now tree-bound (survivors are derived from authenticated rows), so they
    // live in `piece_text_cleanup_pieces_op`. Only tree-free structural rules are
    // exercised here.

    #[test]
    fn piece_text_cleanup_pieces_non_canonical_run_order_rejected() {
        let mut env = pieces_envelope();
        env.runs.reverse();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("ascending"));
    }

    #[test]
    fn piece_text_cleanup_pieces_over_run_cap_rejected() {
        let mut env = pieces_envelope();
        env.runs = (0..(MAX_PIECE_TEXT_CLEANUP_RUNS as i64 + 1))
            .map(|i| PieceTextCleanupRunV1 {
                removals: vec![1_000_000 + i],
            })
            .collect();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("exceeding cap"));
    }

    #[test]
    fn piece_text_cleanup_pieces_over_removal_cap_rejected() {
        let mut env = pieces_envelope();
        // One run that removes more than the per-envelope removal cap.
        env.runs = vec![PieceTextCleanupRunV1 {
            removals: (1..=(MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS as i64 + 1)).collect(),
        }];
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("exceeding cap"));
    }

    #[test]
    fn piece_text_cleanup_buffers_empty_envelope_rejected() {
        let mut env = buffers_envelope();
        env.buffer_removals.clear();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("at least one buffer"));
    }

    #[test]
    fn piece_text_cleanup_buffers_unsorted_or_duplicate_rejected() {
        let mut env = buffers_envelope();
        env.buffer_removals = vec![40, 30];
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("ascending"));

        env.buffer_removals = vec![30, 30];
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("ascending"));
    }

    #[test]
    fn piece_text_cleanup_buffers_over_cap_rejected() {
        let mut env = buffers_envelope();
        env.buffer_removals = (1..=(MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS as i64 + 1)).collect();
        assert!(env
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("exceeding cap"));
    }

    #[test]
    fn piece_text_cleanup_pieces_entry_key_validation() {
        let env = pieces_envelope();
        let kv = env.changelog_entry_kv().unwrap();
        env.validate_entry_key(&kv.key).unwrap();

        // Wrong tag (an edit key) is rejected.
        let wrong_tag = piece_text_edit_key(
            &env.address.table,
            env.address.row_id,
            &env.address.column,
            [0u8; 16],
        );
        assert!(matches!(
            env.validate_entry_key(&wrong_tag),
            Err(ChangelogError::KeyMismatch(_))
        ));

        // A buffers-cleanup key uses a different tag and must be rejected.
        let buffers_tag = piece_text_cleanup_buffers_key(
            &env.address.table,
            env.address.row_id,
            &env.address.column,
            env.op_id,
        );
        assert!(matches!(
            env.validate_entry_key(&buffers_tag),
            Err(ChangelogError::KeyMismatch(_))
        ));

        // Right tag, wrong field.
        let wrong_field = piece_text_cleanup_pieces_key(
            &env.address.table,
            env.address.row_id + 1,
            &env.address.column,
            env.op_id,
        );
        assert!(matches!(
            env.validate_entry_key(&wrong_field),
            Err(ChangelogError::KeyMismatch(_))
        ));
    }

    #[test]
    fn piece_text_cleanup_buffers_entry_key_validation() {
        let env = buffers_envelope();
        let kv = env.changelog_entry_kv().unwrap();
        env.validate_entry_key(&kv.key).unwrap();

        // A pieces-cleanup key uses a different tag and must be rejected.
        let pieces_tag = piece_text_cleanup_pieces_key(
            &env.address.table,
            env.address.row_id,
            &env.address.column,
            env.op_id,
        );
        assert!(matches!(
            env.validate_entry_key(&pieces_tag),
            Err(ChangelogError::KeyMismatch(_))
        ));
    }

    #[test]
    fn piece_text_cleanup_pieces_decode_from_entry_rejects_wrong_shape() {
        let env = pieces_envelope();
        let mut entry = pieces_entry(&env);
        entry.message.op_type = OpType::PieceTextEdit;
        assert!(PieceTextCleanupPiecesEnvelopeV1::decode_from_entry(&entry)
            .unwrap_err()
            .to_string()
            .contains("expected OpType::PieceTextCleanupPieces"));

        let mut entry = pieces_entry(&env);
        entry.message.tree_path = b"/other".to_vec();
        assert!(PieceTextCleanupPiecesEnvelopeV1::decode_from_entry(&entry)
            .unwrap_err()
            .to_string()
            .contains("tree_path"));

        let mut entry = pieces_entry(&env);
        entry
            .message
            .entries
            .push(env.changelog_entry_kv().unwrap());
        assert!(PieceTextCleanupPiecesEnvelopeV1::decode_from_entry(&entry)
            .unwrap_err()
            .to_string()
            .contains("exactly one"));
    }

    #[test]
    fn piece_text_cleanup_buffers_decode_from_entry_rejects_wrong_shape() {
        let env = buffers_envelope();
        let mut entry = buffers_entry(&env);
        entry.message.op_type = OpType::PieceTextCleanupPieces;
        assert!(PieceTextCleanupBuffersEnvelopeV1::decode_from_entry(&entry)
            .unwrap_err()
            .to_string()
            .contains("expected OpType::PieceTextCleanupBuffers"));
    }

    #[test]
    fn piece_text_cleanup_keys_differ_across_op_kinds() {
        let pieces = pieces_envelope();
        let buffers = buffers_envelope();
        let pieces_key = pieces.changelog_entry_kv().unwrap().key;
        let buffers_key = buffers.changelog_entry_kv().unwrap().key;
        assert_ne!(pieces_key, buffers_key);

        let edit = PieceTextEditEnvelopeV1 {
            version: crate::piece_text::PIECE_TEXT_ENVELOPE_VERSION_V1,
            op_id: [1u8; 16],
            address: address(),
            edit: crate::piece_text::PieceTextEditManifest { ops: vec![] },
        };
        let edit_key = piece_text_edit_key(
            &edit.address.table,
            edit.address.row_id,
            &edit.address.column,
            edit.op_id,
        );
        assert_ne!(pieces_key, edit_key);
        assert_ne!(buffers_key, edit_key);
        assert_eq!(ROOT_TREE_PATH, b"/");
    }
}
