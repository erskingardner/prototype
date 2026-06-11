//! Pure in-memory piece-table edit planner.
//!
//! This module is a model/test planner. It takes a caller-supplied snapshot of
//! the `_piecetext_pieces` rows for one document plus pre-existing
//! `_piecetext_buffers` metadata, runs an edit vector against a working copy,
//! and returns the corresponding write batch. Production verification uses the
//! `OpReader`-backed indexed overlay planner in [`crate::piece_text_overlay`].
//!
//! The Merk-side `_piecetext_pieces.buffer_id` index is simulated here by an
//! in-memory `HashMap<i64, Vec<i64>>` (buffer_id -> piece row ids). No Merk,
//! changelog, transport, or encryption work happens in this module.
//!
//! Mirrors the piece-text coordinate-resolution and splice algorithms.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::piece_text::{
    BufferCoord, InsertedBufferManifest, PieceCoord, PieceTextEditEnvelopeV1,
    PieceTextEditItemManifest, MAX_BUFFER_LEN_BYTES,
};
use crate::piece_text_resolution::{
    resolve_coord_core, ResolveCoreResult, ResolveEndpoint, ResolveSource,
};

/// Owner-address columns + cleartext metadata for a `_piecetext_buffers` row that
/// already existed before this edit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferMeta {
    pub id: i64,
    pub owner_table: String,
    pub owner_row_id: i64,
    pub owner_column: String,
    pub author_id: i64,
    pub len_bytes: u32,
}

/// One `_piecetext_pieces` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PieceRow {
    pub id: i64,
    pub list_number: i64,
    pub prev_id: i64,
    pub next_id: i64,
    pub coord: PieceCoord,
}

/// Pre-state snapshot of `_piecetext_pieces` for one `list_number`.
///
/// `head_id` and `tail_id` are 0 when the list is empty.
#[derive(Clone, Debug)]
pub struct PieceSnapshot {
    pub list_number: i64,
    pub head_id: i64,
    pub tail_id: i64,
    pub pieces: Vec<PieceRow>,
    pub pre_piece_next_id: i64,
}

/// Pre-state snapshot of `_piecetext_buffers` rows referenced by the edit.
#[derive(Clone, Debug)]
pub struct BufferSnapshot {
    pub buffers: Vec<BufferMeta>,
    pub pre_buffers_next_id: i64,
}

/// Inputs to [`plan_edit`].
///
/// `address` and `author_id` are server-derived; the planner uses them to
/// fill in `_piecetext_buffers` row metadata for inserted buffers.
#[derive(Clone, Debug)]
pub struct PlannerInput<'a> {
    pub envelope: &'a PieceTextEditEnvelopeV1,
    pub pieces: PieceSnapshot,
    pub buffers: BufferSnapshot,
    pub author_id: i64,
}

/// Errors raised during planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerError {
    UnknownCoordinate {
        coord: BufferCoord,
        purpose: ResolvePurpose,
        reason: String,
    },
    InvalidCoordinate(String),
    InvalidEdit(String),
    BufferNotFound {
        buffer_id: i64,
    },
    ListMismatch {
        row_id: i64,
        expected_list: i64,
        found_list: i64,
    },
    SnapshotInvariant(String),
}

impl std::fmt::Display for PlannerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlannerError::UnknownCoordinate {
                coord,
                purpose,
                reason,
            } => write!(
                f,
                "unknown coordinate (buffer_id={}, byte_pos={}, purpose={:?}): {}",
                coord.buffer_id, coord.byte_pos, purpose, reason
            ),
            PlannerError::InvalidCoordinate(msg) => write!(f, "invalid coordinate: {msg}"),
            PlannerError::InvalidEdit(msg) => write!(f, "invalid edit: {msg}"),
            PlannerError::BufferNotFound { buffer_id } => {
                write!(f, "buffer {buffer_id} not in snapshot")
            }
            PlannerError::ListMismatch {
                row_id,
                expected_list,
                found_list,
            } => write!(
                f,
                "row {row_id} belongs to list {found_list}, expected {expected_list}"
            ),
            PlannerError::SnapshotInvariant(msg) => write!(f, "snapshot invariant: {msg}"),
        }
    }
}

impl std::error::Error for PlannerError {}

/// Tombstone-clamp direction (mirrors §1.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvePurpose {
    InsertAnchor,
    DeleteStart,
    DeleteEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampDirection {
    Forward,
    Backward,
}

impl ResolvePurpose {
    pub(crate) fn clamp_direction(self) -> ClampDirection {
        match self {
            ResolvePurpose::InsertAnchor | ResolvePurpose::DeleteEnd => ClampDirection::Backward,
            ResolvePurpose::DeleteStart => ClampDirection::Forward,
        }
    }
}

/// One simulated lookup over `_piecetext_pieces.buffer_id`, used by tests to
/// observe what the planner asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexLookup {
    pub buffer_id: i64,
    pub returned_row_ids: Vec<i64>,
}

/// One tombstone-clamp walk from `start_row_id` in `direction`. `hops` counts
/// the tombstoned rows skipped. `end_row_id` is the live row landed on, or
/// `None` if the walk hit the chain endpoint (`head_id`/`tail_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClampWalk {
    pub start_row_id: i64,
    pub direction: ClampDirection,
    pub purpose: ResolvePurpose,
    pub hops: u32,
    pub end_row_id: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlannerTrace {
    /// Distinct pre-existing piece rows authenticated by the indexed overlay
    /// planner, sorted by row id. The in-memory model leaves this empty because
    /// its caller already supplied a full snapshot.
    pub authenticated_piece_coords: Vec<(i64, PieceCoord)>,
    pub index_lookups: Vec<IndexLookup>,
    pub clamp_walks: Vec<ClampWalk>,
}

/// Materialised write batch from a planned edit.
///
/// `piece_inserts` is in build order — the verifier expects sequential
/// `new_id` assignment from `pre_piece_next_id`.
/// `piece_updates` is sorted by `id`. `head_update`/`tail_update` are
/// `Some(_)` only when the list endpoint actually changed. Counter bumps are
/// `Some(_)` only when a row was added to the corresponding internal table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlannerOutput {
    pub piece_inserts: Vec<PieceRowInsert>,
    pub piece_updates: Vec<PieceRowUpdate>,
    pub buffer_inserts: Vec<BufferRowInsert>,
    pub head_update: Option<i64>,
    pub tail_update: Option<i64>,
    pub piece_next_id_post: Option<i64>,
    pub buffers_next_id_post: Option<i64>,
    pub trace: PlannerTrace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceRowInsert {
    pub new_id: i64,
    pub list_number: i64,
    pub prev_id: i64,
    pub next_id: i64,
    pub coord: PieceCoord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceRowUpdate {
    pub id: i64,
    pub prev_id: Option<i64>,
    pub next_id: Option<i64>,
    pub coord: Option<PieceCoord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferRowInsert {
    pub new_id: i64,
    pub owner_table: String,
    pub owner_row_id: i64,
    pub owner_column: String,
    pub author_id: i64,
    pub len_bytes: u32,
    pub ciphertext_value_hash: [u8; 32],
}

/// Plan a piece-text edit against an in-memory snapshot.
///
/// This is the model/test planner only. Production verification
/// (`PieceTextEditOp::extract_and_validate`) runs the `OpReader`-backed
/// [`crate::piece_text_overlay::IndexedPieceEditPlanner`], which authenticates
/// rows on demand instead of taking a full-document snapshot. `plan_edit` is
/// kept as a pure oracle for the planner unit tests and the SDK concurrency
/// fuzz/stress harness; it must not be called from any production code path.
pub fn plan_edit(input: PlannerInput<'_>) -> Result<PlannerOutput, PlannerError> {
    let mut wc = WorkingCopy::from_snapshot(&input.pieces, &input.buffers)?;
    let mut trace = PlannerTrace::default();
    let mut buffer_inserts: Vec<BufferRowInsert> = Vec::new();
    let mut allocated_buffer_ids: HashSet<i64> = HashSet::new();
    let mut next_buffer_id = input.buffers.pre_buffers_next_id;

    let address = &input.envelope.address;
    for (i, item) in input.envelope.edit.ops.iter().enumerate() {
        match item {
            PieceTextEditItemManifest::Insert { at, inserted } => {
                if at.buffer_id != 0 && allocated_buffer_ids.contains(&at.buffer_id) {
                    return Err(PlannerError::InvalidCoordinate(format!(
                        "edit op {i} targets buffer_id {} allocated by an earlier Insert in this same edit",
                        at.buffer_id
                    )));
                }
                if at.buffer_id != 0 {
                    require_buffer(&wc, at.buffer_id)?;
                }
                let new_buffer_id = next_buffer_id;
                next_buffer_id = next_buffer_id.checked_add(1).ok_or_else(|| {
                    PlannerError::InvalidEdit(
                        "_piecetext_buffers next_id counter overflowed i64".to_string(),
                    )
                })?;
                allocated_buffer_ids.insert(new_buffer_id);
                buffer_inserts.push(BufferRowInsert {
                    new_id: new_buffer_id,
                    owner_table: address.table.clone(),
                    owner_row_id: address.row_id,
                    owner_column: address.column.clone(),
                    author_id: input.author_id,
                    len_bytes: inserted.len_bytes,
                    ciphertext_value_hash: inserted.ciphertext_value_hash,
                });
                apply_insert(&mut wc, &mut trace, *at, new_buffer_id, inserted)?;
            }
            PieceTextEditItemManifest::Delete { start, end } => {
                if start.buffer_id != 0 && allocated_buffer_ids.contains(&start.buffer_id) {
                    return Err(PlannerError::InvalidCoordinate(format!(
                        "edit op {i} delete start targets buffer_id {} allocated by an earlier Insert in this same edit",
                        start.buffer_id
                    )));
                }
                if end.buffer_id != 0 && allocated_buffer_ids.contains(&end.buffer_id) {
                    return Err(PlannerError::InvalidCoordinate(format!(
                        "edit op {i} delete end targets buffer_id {} allocated by an earlier Insert in this same edit",
                        end.buffer_id
                    )));
                }
                if start.buffer_id != 0 {
                    require_buffer(&wc, start.buffer_id)?;
                }
                if end.buffer_id != 0 {
                    require_buffer(&wc, end.buffer_id)?;
                }
                apply_delete(&mut wc, &mut trace, *start, *end)?;
            }
        }
    }

    let mut piece_inserts: Vec<PieceRowInsert> = Vec::new();
    for new_id in &wc.new_piece_ids {
        let row = wc
            .pieces
            .get(new_id)
            .expect("new piece id must exist in working copy");
        piece_inserts.push(PieceRowInsert {
            new_id: row.current.id,
            list_number: row.current.list_number,
            prev_id: row.current.prev_id,
            next_id: row.current.next_id,
            coord: row.current.coord,
        });
    }

    let mut piece_updates: Vec<PieceRowUpdate> = Vec::new();
    let mut updated_ids: Vec<i64> = wc
        .pieces
        .iter()
        .filter_map(|(id, row)| {
            if !row.is_existing() {
                return None;
            }
            let prev_changed = row.original_prev_id != Some(row.current.prev_id);
            let next_changed = row.original_next_id != Some(row.current.next_id);
            let coord_changed = row.original_coord != Some(row.current.coord);
            if prev_changed || next_changed || coord_changed {
                Some(*id)
            } else {
                None
            }
        })
        .collect();
    updated_ids.sort_unstable();
    for id in updated_ids {
        let row = &wc.pieces[&id];
        let prev_id = if row.original_prev_id != Some(row.current.prev_id) {
            Some(row.current.prev_id)
        } else {
            None
        };
        let next_id = if row.original_next_id != Some(row.current.next_id) {
            Some(row.current.next_id)
        } else {
            None
        };
        let coord = if row.original_coord != Some(row.current.coord) {
            Some(row.current.coord)
        } else {
            None
        };
        piece_updates.push(PieceRowUpdate {
            id,
            prev_id,
            next_id,
            coord,
        });
    }

    let head_update = if wc.head_id != input.pieces.head_id {
        Some(wc.head_id)
    } else {
        None
    };
    let tail_update = if wc.tail_id != input.pieces.tail_id {
        Some(wc.tail_id)
    } else {
        None
    };

    let piece_next_id_post = if wc.new_piece_ids.is_empty() {
        None
    } else {
        Some(wc.next_piece_id)
    };
    let buffers_next_id_post = if buffer_inserts.is_empty() {
        None
    } else {
        Some(next_buffer_id)
    };

    Ok(PlannerOutput {
        piece_inserts,
        piece_updates,
        buffer_inserts,
        head_update,
        tail_update,
        piece_next_id_post,
        buffers_next_id_post,
        trace,
    })
}

// ---------- working copy ----------

#[derive(Debug, Clone)]
struct PieceRowState {
    current: PieceRow,
    original_prev_id: Option<i64>,
    original_next_id: Option<i64>,
    original_coord: Option<PieceCoord>,
}

impl PieceRowState {
    fn is_existing(&self) -> bool {
        self.original_prev_id.is_some()
            || self.original_next_id.is_some()
            || self.original_coord.is_some()
    }
}

#[derive(Debug, Clone)]
struct WorkingCopy {
    list_number: i64,
    head_id: i64,
    tail_id: i64,
    pieces: BTreeMap<i64, PieceRowState>,
    /// `_piecetext_pieces.buffer_id` simulated index. Buffer ids never
    /// changes for an existing row, so an entry is only ever appended (when a
    /// new piece row is inserted). Entries are never removed.
    buffer_id_index: HashMap<i64, Vec<i64>>,
    next_piece_id: i64,
    new_piece_ids: Vec<i64>,
    buffers: HashMap<i64, BufferMeta>,
}

impl WorkingCopy {
    fn from_snapshot(
        pieces: &PieceSnapshot,
        buffers: &BufferSnapshot,
    ) -> Result<Self, PlannerError> {
        if pieces.pre_piece_next_id < 1 {
            return Err(PlannerError::SnapshotInvariant(
                "pre_piece_next_id must be >= 1".to_string(),
            ));
        }
        if buffers.pre_buffers_next_id < 1 {
            return Err(PlannerError::SnapshotInvariant(
                "pre_buffers_next_id must be >= 1".to_string(),
            ));
        }
        if pieces.list_number <= 0 {
            return Err(PlannerError::SnapshotInvariant(
                "list_number must be positive".to_string(),
            ));
        }

        let mut state: BTreeMap<i64, PieceRowState> = BTreeMap::new();
        let mut index: HashMap<i64, Vec<i64>> = HashMap::new();
        for row in &pieces.pieces {
            if row.id <= 0 {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "piece row id must be positive (got {})",
                    row.id
                )));
            }
            if row.id >= pieces.pre_piece_next_id {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "piece row id {} is >= pre_piece_next_id {}",
                    row.id, pieces.pre_piece_next_id
                )));
            }
            if row.list_number != pieces.list_number {
                return Err(PlannerError::ListMismatch {
                    row_id: row.id,
                    expected_list: pieces.list_number,
                    found_list: row.list_number,
                });
            }
            if row.coord.len_bytes == 0 {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "piece row {} has len_bytes == 0",
                    row.id
                )));
            }
            if state
                .insert(
                    row.id,
                    PieceRowState {
                        current: row.clone(),
                        original_prev_id: Some(row.prev_id),
                        original_next_id: Some(row.next_id),
                        original_coord: Some(row.coord),
                    },
                )
                .is_some()
            {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "duplicate piece row id {} in snapshot",
                    row.id
                )));
            }
            index.entry(row.coord.buffer_id).or_default().push(row.id);
        }

        // Validate doubly-linked invariants and head/tail consistency.
        if pieces.head_id != 0 {
            let head = state.get(&pieces.head_id).ok_or_else(|| {
                PlannerError::SnapshotInvariant(format!(
                    "head_id {} not in snapshot",
                    pieces.head_id
                ))
            })?;
            if head.current.prev_id != 0 {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "head row {} has non-zero prev_id {}",
                    pieces.head_id, head.current.prev_id
                )));
            }
        }
        if pieces.tail_id != 0 {
            let tail = state.get(&pieces.tail_id).ok_or_else(|| {
                PlannerError::SnapshotInvariant(format!(
                    "tail_id {} not in snapshot",
                    pieces.tail_id
                ))
            })?;
            if tail.current.next_id != 0 {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "tail row {} has non-zero next_id {}",
                    pieces.tail_id, tail.current.next_id
                )));
            }
        }
        if (pieces.head_id == 0) != (pieces.tail_id == 0) {
            return Err(PlannerError::SnapshotInvariant(
                "head_id and tail_id must both be 0 or both be non-zero".to_string(),
            ));
        }

        for row in state.values() {
            if row.current.prev_id != 0 {
                let prev = state.get(&row.current.prev_id).ok_or_else(|| {
                    PlannerError::SnapshotInvariant(format!(
                        "row {} prev_id {} not in snapshot",
                        row.current.id, row.current.prev_id
                    ))
                })?;
                if prev.current.next_id != row.current.id {
                    return Err(PlannerError::SnapshotInvariant(format!(
                        "row {} prev/next pointers inconsistent",
                        row.current.id
                    )));
                }
            } else if row.current.id != pieces.head_id {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "row {} has prev_id 0 but is not head",
                    row.current.id
                )));
            }
            if row.current.next_id != 0 {
                let next = state.get(&row.current.next_id).ok_or_else(|| {
                    PlannerError::SnapshotInvariant(format!(
                        "row {} next_id {} not in snapshot",
                        row.current.id, row.current.next_id
                    ))
                })?;
                if next.current.prev_id != row.current.id {
                    return Err(PlannerError::SnapshotInvariant(format!(
                        "row {} prev/next pointers inconsistent",
                        row.current.id
                    )));
                }
            } else if row.current.id != pieces.tail_id {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "row {} has next_id 0 but is not tail",
                    row.current.id
                )));
            }
        }

        // Buffer metadata + per-piece range checks.
        let mut buffer_map: HashMap<i64, BufferMeta> = HashMap::new();
        for buf in &buffers.buffers {
            if buf.id <= 0 {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "buffer id must be positive (got {})",
                    buf.id
                )));
            }
            if buf.id >= buffers.pre_buffers_next_id {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "buffer id {} is >= pre_buffers_next_id {}",
                    buf.id, buffers.pre_buffers_next_id
                )));
            }
            if buf.len_bytes == 0 || buf.len_bytes > MAX_BUFFER_LEN_BYTES {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "buffer {} has invalid len_bytes {}",
                    buf.id, buf.len_bytes
                )));
            }
            if buffer_map.insert(buf.id, buf.clone()).is_some() {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "duplicate buffer id {} in snapshot",
                    buf.id
                )));
            }
        }
        for row in state.values() {
            let buf = buffer_map
                .get(&row.current.coord.buffer_id)
                .ok_or_else(|| {
                    PlannerError::SnapshotInvariant(format!(
                        "piece row {} references buffer_id {} not in snapshot",
                        row.current.id, row.current.coord.buffer_id
                    ))
                })?;
            let end = row
                .current
                .coord
                .start_byte
                .checked_add(row.current.coord.len_bytes)
                .ok_or_else(|| {
                    PlannerError::SnapshotInvariant(format!(
                        "piece row {} coord overflow",
                        row.current.id
                    ))
                })?;
            if end > buf.len_bytes {
                return Err(PlannerError::SnapshotInvariant(format!(
                    "piece row {} range exceeds buffer {} len_bytes ({} > {})",
                    row.current.id, buf.id, end, buf.len_bytes
                )));
            }
        }

        Ok(WorkingCopy {
            list_number: pieces.list_number,
            head_id: pieces.head_id,
            tail_id: pieces.tail_id,
            pieces: state,
            buffer_id_index: index,
            next_piece_id: pieces.pre_piece_next_id,
            new_piece_ids: Vec::new(),
            buffers: buffer_map,
        })
    }

    fn alloc_piece_id(&mut self) -> Result<i64, PlannerError> {
        let id = self.next_piece_id;
        self.next_piece_id = self.next_piece_id.checked_add(1).ok_or_else(|| {
            PlannerError::InvalidEdit(
                "_piecetext_pieces next_id counter overflowed i64".to_string(),
            )
        })?;
        Ok(id)
    }

    fn insert_new_row(
        &mut self,
        id: i64,
        prev_id: i64,
        next_id: i64,
        coord: PieceCoord,
    ) -> Result<(), PlannerError> {
        let row = PieceRow {
            id,
            list_number: self.list_number,
            prev_id,
            next_id,
            coord,
        };
        self.buffer_id_index
            .entry(coord.buffer_id)
            .or_default()
            .push(id);
        self.new_piece_ids.push(id);
        if self
            .pieces
            .insert(
                id,
                PieceRowState {
                    current: row,
                    original_prev_id: None,
                    original_next_id: None,
                    original_coord: None,
                },
            )
            .is_some()
        {
            return Err(PlannerError::InvalidEdit(format!(
                "double-allocated piece row id {id}"
            )));
        }
        Ok(())
    }

    fn set_prev(&mut self, id: i64, prev_id: i64) {
        let row = self
            .pieces
            .get_mut(&id)
            .expect("set_prev on missing row id");
        row.current.prev_id = prev_id;
    }

    fn set_next(&mut self, id: i64, next_id: i64) {
        let row = self
            .pieces
            .get_mut(&id)
            .expect("set_next on missing row id");
        row.current.next_id = next_id;
    }

    fn set_coord(&mut self, id: i64, coord: PieceCoord) {
        let row = self
            .pieces
            .get_mut(&id)
            .expect("set_coord on missing row id");
        row.current.coord = coord;
    }

    fn row(&self, id: i64) -> &PieceRow {
        &self.pieces[&id].current
    }
}

fn require_buffer(wc: &WorkingCopy, buffer_id: i64) -> Result<(), PlannerError> {
    if buffer_id <= 0 {
        return Err(PlannerError::InvalidCoordinate(format!(
            "non-DOCUMENT_START coordinate must reference buffer_id > 0, got {buffer_id}"
        )));
    }
    if !wc.buffers.contains_key(&buffer_id) {
        return Err(PlannerError::BufferNotFound { buffer_id });
    }
    Ok(())
}

// ---------- coord resolution ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolveMatch {
    /// Coord is `DOCUMENT_START` (the only "before the chain head" form
    /// produced without a clamp walk).
    BeforeHead,
    /// Resolved to a row currently in the chain. `k = byte_pos - row.start_byte`.
    InRow { row_id: i64, k: u32 },
    /// Coord landed on a tombstone-clamp anchor: the live row reached after a
    /// non-zero clamp walk. The new piece (for inserts) splices against this
    /// row at its end (back-clamp) or start (forward-clamp).
    AfterClamp { row_id: i64 },
    /// Backward-clamp reached the chain head without finding a live row.
    BeforeHeadClamped,
    /// Forward-clamp reached the chain tail without finding a live row.
    AfterTailClamped,
}

fn resolve_coord(
    wc: &WorkingCopy,
    coord: BufferCoord,
    purpose: ResolvePurpose,
    trace: &mut PlannerTrace,
) -> Result<ResolveMatch, PlannerError> {
    let output = {
        let mut source = PlannerResolveSource { wc, trace };
        resolve_coord_core(&mut source, coord, purpose)?
    };
    record_planner_clamp_walk(&output.result, purpose, trace);

    Ok(match output.result {
        ResolveCoreResult::DocumentStart { .. } => ResolveMatch::BeforeHead,
        ResolveCoreResult::InRow { row, offset } => ResolveMatch::InRow {
            row_id: row.id,
            k: offset,
        },
        ResolveCoreResult::ClampedToRow { row, .. } => ResolveMatch::AfterClamp { row_id: row.id },
        ResolveCoreResult::ClampedBeforeHead { .. } => ResolveMatch::BeforeHeadClamped,
        ResolveCoreResult::ClampedAfterTail { .. } => ResolveMatch::AfterTailClamped,
    })
}

struct PlannerResolveSource<'a> {
    wc: &'a WorkingCopy,
    trace: &'a mut PlannerTrace,
}

impl ResolveSource for PlannerResolveSource<'_> {
    type Error = PlannerError;

    fn list_number(&self) -> i64 {
        self.wc.list_number
    }

    fn candidate_row_ids(&mut self, buffer_id: i64) -> Result<Vec<i64>, Self::Error> {
        let row_ids = self
            .wc
            .buffer_id_index
            .get(&buffer_id)
            .cloned()
            .unwrap_or_default();
        self.trace.index_lookups.push(IndexLookup {
            buffer_id,
            returned_row_ids: row_ids.clone(),
        });
        Ok(row_ids)
    }

    fn read_row(&mut self, row_id: i64) -> Result<PieceRow, Self::Error> {
        self.wc
            .pieces
            .get(&row_id)
            .map(|row| row.current.clone())
            .ok_or_else(|| {
                PlannerError::SnapshotInvariant(format!("row {row_id} not in working copy"))
            })
    }

    fn read_endpoint(&mut self, endpoint: ResolveEndpoint) -> Result<i64, Self::Error> {
        Ok(match endpoint {
            ResolveEndpoint::Head => self.wc.head_id,
            ResolveEndpoint::Tail => self.wc.tail_id,
        })
    }

    fn invalid_coordinate(&self, message: String) -> Self::Error {
        PlannerError::InvalidCoordinate(message)
    }

    fn unknown_coordinate(
        &self,
        coord: BufferCoord,
        purpose: ResolvePurpose,
        reason: String,
    ) -> Self::Error {
        PlannerError::UnknownCoordinate {
            coord,
            purpose,
            reason,
        }
    }

    fn invariant(&self, message: String) -> Self::Error {
        PlannerError::SnapshotInvariant(message)
    }
}

fn record_planner_clamp_walk(
    result: &ResolveCoreResult,
    purpose: ResolvePurpose,
    trace: &mut PlannerTrace,
) {
    let Some((start_row_id, direction, hops, end_row_id)) = (match result {
        ResolveCoreResult::ClampedToRow {
            row,
            start_row_id,
            direction,
            hops,
        } => Some((*start_row_id, *direction, *hops, Some(row.id))),
        ResolveCoreResult::ClampedBeforeHead {
            start_row_id,
            direction,
            hops,
            ..
        }
        | ResolveCoreResult::ClampedAfterTail {
            start_row_id,
            direction,
            hops,
            ..
        } => Some((*start_row_id, *direction, *hops, None)),
        ResolveCoreResult::DocumentStart { .. } | ResolveCoreResult::InRow { .. } => None,
    }) else {
        return;
    };
    trace.clamp_walks.push(ClampWalk {
        start_row_id,
        direction,
        purpose,
        hops,
        end_row_id,
    });
}

// ---------- insert ----------

// UTF-32 alignment is an inductive invariant of the tree, not re-derived here:
//
//   * The generic row `Insert` op allocates a PieceText cell as an empty chain
//     (no byte ranges at all).
//   * `PieceTextEdit` is the only op that introduces new byte ranges, and the
//     verifier enforces 4-byte alignment on its envelope inputs up front
//     (`BufferCoord::validate_shape`, `InsertedBufferManifest::validate`).
//   * This commit introduces no other op that mutates `start_byte`/`len_bytes`.
//
// Every coordinate the splice helpers below derive is `start_byte`, `start_byte
// + k`, `len_bytes`, `len_bytes - k`, or `k = byte_pos - start_byte` for inputs
// that are already multiples of 4, so the results are multiples of 4 too. The
// planner therefore stays alignment-agnostic; the verifier re-checks the
// derived coords it actually writes in `materialise_planner_output` as
// defense-in-depth against a buggy or hostile planner.
fn apply_insert(
    wc: &mut WorkingCopy,
    trace: &mut PlannerTrace,
    at: BufferCoord,
    new_buffer_id: i64,
    inserted: &InsertedBufferManifest,
) -> Result<(), PlannerError> {
    if inserted.len_bytes == 0 {
        return Err(PlannerError::InvalidEdit(
            "Insert.len_bytes must be > 0".to_string(),
        ));
    }
    if inserted.len_bytes > MAX_BUFFER_LEN_BYTES {
        return Err(PlannerError::InvalidEdit(format!(
            "Insert.len_bytes {} exceeds MAX_BUFFER_LEN_BYTES {MAX_BUFFER_LEN_BYTES}",
            inserted.len_bytes
        )));
    }

    let resolution = resolve_coord(wc, at, ResolvePurpose::InsertAnchor, trace)?;
    let splice = derive_insert_splice(wc, resolution, at)?;
    let new_coord = PieceCoord {
        buffer_id: new_buffer_id,
        start_byte: 0,
        len_bytes: inserted.len_bytes,
        tombstone: false,
    };

    match splice {
        InsertSplice::AtHead => {
            let new_id = wc.alloc_piece_id()?;
            let old_head = wc.head_id;
            wc.insert_new_row(new_id, 0, old_head, new_coord)?;
            if old_head != 0 {
                wc.set_prev(old_head, new_id);
            }
            wc.head_id = new_id;
            if wc.tail_id == 0 {
                wc.tail_id = new_id;
            }
        }
        InsertSplice::AfterRow { id: anchor_id } => {
            let s = wc.row(anchor_id).next_id;
            let new_id = wc.alloc_piece_id()?;
            wc.insert_new_row(new_id, anchor_id, s, new_coord)?;
            wc.set_next(anchor_id, new_id);
            if s != 0 {
                wc.set_prev(s, new_id);
            } else {
                wc.tail_id = new_id;
            }
        }
        InsertSplice::SplitRow { id: anchor_id, k } => {
            let p = wc.row(anchor_id).clone();
            let s = p.next_id;
            // §6.3 mutation order: N gets the lower new id, R the next.
            let n_id = wc.alloc_piece_id()?;
            let r_id = wc.alloc_piece_id()?;

            let r_coord = PieceCoord {
                buffer_id: p.coord.buffer_id,
                start_byte: p.coord.start_byte + k,
                len_bytes: p.coord.len_bytes - k,
                tombstone: p.coord.tombstone,
            };
            let new_p_coord = PieceCoord {
                buffer_id: p.coord.buffer_id,
                start_byte: p.coord.start_byte,
                len_bytes: k,
                tombstone: p.coord.tombstone,
            };

            wc.set_coord(p.id, new_p_coord);
            wc.insert_new_row(n_id, p.id, r_id, new_coord)?;
            wc.insert_new_row(r_id, n_id, s, r_coord)?;
            wc.set_next(p.id, n_id);
            if s != 0 {
                wc.set_prev(s, r_id);
            } else {
                wc.tail_id = r_id;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InsertSplice {
    AtHead,
    AfterRow { id: i64 },
    SplitRow { id: i64, k: u32 },
}

fn derive_insert_splice(
    wc: &WorkingCopy,
    resolution: ResolveMatch,
    at: BufferCoord,
) -> Result<InsertSplice, PlannerError> {
    match resolution {
        ResolveMatch::BeforeHead | ResolveMatch::BeforeHeadClamped => Ok(InsertSplice::AtHead),
        ResolveMatch::AfterTailClamped => {
            // Should never happen for InsertAnchor (it back-clamps), but be
            // explicit so a future regression is caught.
            Err(PlannerError::InvalidCoordinate(format!(
                "insert at {at:?} forward-clamped past tail; InsertAnchor should back-clamp"
            )))
        }
        ResolveMatch::AfterClamp { row_id } => {
            // Tombstone-clamped backward to a live predecessor; splice between
            // it and the start of the tombstoned run (its current next_id).
            Ok(InsertSplice::AfterRow { id: row_id })
        }
        ResolveMatch::InRow { row_id, k } => {
            let row = wc.row(row_id);
            if k == row.coord.len_bytes {
                // Boundary at end of row: predecessor wins => splice after row.
                Ok(InsertSplice::AfterRow { id: row.id })
            } else if k == 0 {
                // Boundary at start of row: no same-buffer predecessor at this
                // boundary. Splice between row.prev_id and row.
                if row.prev_id == 0 {
                    Ok(InsertSplice::AtHead)
                } else {
                    Ok(InsertSplice::AfterRow { id: row.prev_id })
                }
            } else {
                Ok(InsertSplice::SplitRow { id: row_id, k })
            }
        }
    }
}

// ---------- delete ----------

/// Canonical, totally-ordered delete position.
///
/// `BeforeHead` < every `InRow` < `AfterTail`. Equality is structural.
///
/// Canonical form keeps `k` strictly inside `(0, row.len_bytes]`: any input
/// position at `(row, k = 0)` (a row's left edge) is normalised to the live
/// predecessor's right edge, walking past tombstones. Any input position at
/// `(row, k = row.len_bytes)` whose chain has no live successor is
/// normalised to `AfterTail`. This matches §4.1's "predecessor side wins"
/// rule and ensures two coords that map to the same rendered byte gap
/// produce structurally equal `DeletePos`es.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeletePos {
    BeforeHead,
    InRow { row_id: i64, k: u32 },
    AfterTail,
}

fn apply_delete(
    wc: &mut WorkingCopy,
    trace: &mut PlannerTrace,
    start: BufferCoord,
    end: BufferCoord,
) -> Result<(), PlannerError> {
    let start = resolve_delete_start(wc, start, trace)?;
    let end = resolve_delete_end(wc, end, trace)?;
    use std::cmp::Ordering;
    match compare_positions(wc, start, end)? {
        Ordering::Equal => Ok(()),
        Ordering::Greater => Err(PlannerError::InvalidEdit(
            "delete start resolved past delete end".to_string(),
        )),
        Ordering::Less => execute_delete(wc, start, end),
    }
}

fn resolve_delete_start(
    wc: &WorkingCopy,
    coord: BufferCoord,
    trace: &mut PlannerTrace,
) -> Result<DeletePos, PlannerError> {
    let resolution = resolve_coord(wc, coord, ResolvePurpose::DeleteStart, trace)?;
    Ok(match resolution {
        ResolveMatch::BeforeHead => DeletePos::BeforeHead,
        ResolveMatch::AfterTailClamped => DeletePos::AfterTail,
        ResolveMatch::AfterClamp { row_id } => canonicalize_in_row(wc, row_id, 0),
        ResolveMatch::InRow { row_id, k } => canonicalize_in_row(wc, row_id, k),
        ResolveMatch::BeforeHeadClamped => {
            return Err(PlannerError::SnapshotInvariant(
                "DeleteStart should never produce a backward clamp result".to_string(),
            ))
        }
    })
}

fn resolve_delete_end(
    wc: &WorkingCopy,
    coord: BufferCoord,
    trace: &mut PlannerTrace,
) -> Result<DeletePos, PlannerError> {
    let resolution = resolve_coord(wc, coord, ResolvePurpose::DeleteEnd, trace)?;
    Ok(match resolution {
        ResolveMatch::BeforeHead | ResolveMatch::BeforeHeadClamped => DeletePos::BeforeHead,
        ResolveMatch::AfterClamp { row_id } => {
            let len = wc.row(row_id).coord.len_bytes;
            canonicalize_in_row(wc, row_id, len)
        }
        ResolveMatch::InRow { row_id, k } => canonicalize_in_row(wc, row_id, k),
        ResolveMatch::AfterTailClamped => {
            return Err(PlannerError::SnapshotInvariant(
                "DeleteEnd should never produce a forward clamp result".to_string(),
            ))
        }
    })
}

/// Canonicalise a `(row_id, k)` anchor (where `row_id` is a live row produced
/// by the resolver, and `k ∈ [0, row.len_bytes]`) into a [`DeletePos`].
///
/// `k == 0` ("left edge") is rewritten to the live predecessor's right edge,
/// or `BeforeHead` if no live predecessor exists. `k == row.len_bytes`
/// ("right edge") collapses to `AfterTail` only when no live successor
/// exists; otherwise it is kept as-is — that is the canonical "after row"
/// form (§4.1 predecessor side wins).
fn canonicalize_in_row(wc: &WorkingCopy, row_id: i64, k: u32) -> DeletePos {
    let row = wc.row(row_id);
    if k == 0 {
        let mut cursor = row.prev_id;
        while cursor != 0 {
            let prev = wc.row(cursor);
            if !prev.coord.tombstone {
                return DeletePos::InRow {
                    row_id: cursor,
                    k: prev.coord.len_bytes,
                };
            }
            cursor = prev.prev_id;
        }
        return DeletePos::BeforeHead;
    }
    if k == row.coord.len_bytes {
        let mut cursor = row.next_id;
        while cursor != 0 {
            let next = wc.row(cursor);
            if !next.coord.tombstone {
                return DeletePos::InRow { row_id, k };
            }
            cursor = next.next_id;
        }
        return DeletePos::AfterTail;
    }
    DeletePos::InRow { row_id, k }
}

fn compare_positions(
    wc: &WorkingCopy,
    a: DeletePos,
    b: DeletePos,
) -> Result<std::cmp::Ordering, PlannerError> {
    use std::cmp::Ordering;
    // Special case: in an empty or all-tombstoned chain there is no live
    // content, so `BeforeHead` and `AfterTail` collapse to the same rendered
    // byte gap (the zero-length document). Endpoints
    // that clamp to the same rendered position are a no-op, not an inverted
    // delete; e.g. a DeleteStart inside a tombstoned suffix forward-clamps
    // to AfterTail while a DeleteEnd inside the same tombstoned history
    // back-clamps to BeforeHead, and that pair must compare equal.
    if first_live_row(wc).is_none()
        && matches!(a, DeletePos::BeforeHead | DeletePos::AfterTail)
        && matches!(b, DeletePos::BeforeHead | DeletePos::AfterTail)
    {
        return Ok(Ordering::Equal);
    }
    Ok(match (a, b) {
        (DeletePos::BeforeHead, DeletePos::BeforeHead) => Ordering::Equal,
        (DeletePos::BeforeHead, _) => Ordering::Less,
        (_, DeletePos::BeforeHead) => Ordering::Greater,
        (DeletePos::AfterTail, DeletePos::AfterTail) => Ordering::Equal,
        (DeletePos::AfterTail, _) => Ordering::Greater,
        (_, DeletePos::AfterTail) => Ordering::Less,
        (DeletePos::InRow { row_id: r1, k: k1 }, DeletePos::InRow { row_id: r2, k: k2 }) => {
            if r1 == r2 {
                k1.cmp(&k2)
            } else if chain_walk_lt(wc, r1, r2)? {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    })
}

// Complexity: O(n) in chain length per call — it walks forward from `a_id`
// looking for `b_id`. `compare_positions` invokes it once per delete to order
// the resolved start/end, so a document of deletes is O(deletes · n), i.e.
// quadratic at the ~10k-piece-row document target. Kept linear-per-call (no
// position cache) because the planner runs once per edit and the constant is
// small; revisit with an in-chain order index if the row target grows.
fn chain_walk_lt(wc: &WorkingCopy, a_id: i64, b_id: i64) -> Result<bool, PlannerError> {
    if a_id == b_id {
        return Ok(false);
    }
    let mut cursor = wc.row(a_id).next_id;
    let cap = wc.pieces.len() + 4;
    let mut hops = 0;
    while cursor != 0 {
        if cursor == b_id {
            return Ok(true);
        }
        cursor = wc.row(cursor).next_id;
        hops += 1;
        if hops > cap {
            return Err(PlannerError::SnapshotInvariant(
                "chain walk exceeded snapshot length".to_string(),
            ));
        }
    }
    Ok(false)
}

fn first_live_row(wc: &WorkingCopy) -> Option<i64> {
    let mut cursor = wc.head_id;
    while cursor != 0 {
        let row = wc.row(cursor);
        if !row.coord.tombstone {
            return Some(cursor);
        }
        cursor = row.next_id;
    }
    None
}

fn last_live_row(wc: &WorkingCopy) -> Option<i64> {
    let mut cursor = wc.tail_id;
    while cursor != 0 {
        let row = wc.row(cursor);
        if !row.coord.tombstone {
            return Some(cursor);
        }
        cursor = row.prev_id;
    }
    None
}

fn next_live_row(wc: &WorkingCopy, row_id: i64) -> Option<i64> {
    let mut cursor = wc.row(row_id).next_id;
    while cursor != 0 {
        let row = wc.row(cursor);
        if !row.coord.tombstone {
            return Some(cursor);
        }
        cursor = row.next_id;
    }
    None
}

/// Action to take on the first row of a multi-row delete (or the only row of
/// a single-row delete).
#[derive(Debug, Clone, Copy)]
enum FirstSpec {
    /// Whole row is in the delete range. `Some(id)` if there is a row to act
    /// on; `None` if the start position has no live successor in the chain.
    Whole(Option<i64>),
    /// Ragged-left cut at offset `k`.
    Ragged { row_id: i64, k: u32 },
}

#[derive(Debug, Clone, Copy)]
enum LastSpec {
    /// Whole row is in the delete range.
    Whole(Option<i64>),
    /// Ragged-right cut at offset `k`.
    Ragged { row_id: i64, k: u32 },
}

fn execute_delete(
    wc: &mut WorkingCopy,
    start: DeletePos,
    end: DeletePos,
) -> Result<(), PlannerError> {
    let first = match start {
        DeletePos::BeforeHead => FirstSpec::Whole(first_live_row(wc)),
        DeletePos::InRow { row_id, k } => {
            let row_len = wc.row(row_id).coord.len_bytes;
            if k == row_len {
                // Right edge of `row_id`: row itself is *not* deleted; first
                // affected row is the next live row in chain order. Canonical
                // form guarantees a live successor exists.
                FirstSpec::Whole(next_live_row(wc, row_id))
            } else {
                // Canonical form ensures k > 0 here, so this is a true
                // ragged-left.
                FirstSpec::Ragged { row_id, k }
            }
        }
        DeletePos::AfterTail => return Ok(()),
    };
    let last = match end {
        DeletePos::AfterTail => LastSpec::Whole(last_live_row(wc)),
        DeletePos::InRow { row_id, k } => {
            let row_len = wc.row(row_id).coord.len_bytes;
            if k == row_len {
                LastSpec::Whole(Some(row_id))
            } else {
                // Canonical form ensures k > 0 here, so this is a true
                // ragged-right (k < row_len).
                LastSpec::Ragged { row_id, k }
            }
        }
        DeletePos::BeforeHead => return Ok(()),
    };

    let first_action_row: Option<i64> = match first {
        FirstSpec::Whole(opt) => opt,
        FirstSpec::Ragged { row_id, .. } => Some(row_id),
    };
    let last_action_row: Option<i64> = match last {
        LastSpec::Whole(opt) => opt,
        LastSpec::Ragged { row_id, .. } => Some(row_id),
    };
    let (first_id, last_id) = match (first_action_row, last_action_row) {
        (Some(a), Some(b)) => (a, b),
        _ => return Ok(()),
    };

    if first_id == last_id {
        let row = wc.row(first_id).clone();
        let k1 = match first {
            FirstSpec::Whole(_) => 0,
            FirstSpec::Ragged { k, .. } => k,
        };
        let k2 = match last {
            LastSpec::Whole(_) => row.coord.len_bytes,
            LastSpec::Ragged { k, .. } => k,
        };
        debug_assert!(k1 < k2);
        if k1 == 0 && k2 == row.coord.len_bytes {
            tombstone_in_place(wc, first_id);
        } else if k1 == 0 {
            ragged_right_within_row(wc, row, k2)?;
        } else if k2 == row.coord.len_bytes {
            ragged_left_within_row(wc, row, k1)?;
        } else {
            ragged_center(wc, row, k1, k2)?;
        }
        return Ok(());
    }

    // Multi-row case.
    match first {
        FirstSpec::Whole(_) => tombstone_in_place(wc, first_id),
        FirstSpec::Ragged { row_id, k } => {
            let row = wc.row(row_id).clone();
            ragged_left_within_row(wc, row, k)?;
        }
    }

    // Interior tombstone walk: O(span) in the number of rows between the first
    // and last affected row — up to O(n) for a delete that spans the whole
    // chain, so quadratic across a document's worth of deletes at the ~10k-row
    // target. Each interior row must be visited to tombstone it, so this walk is
    // inherent to the linked-list piece table; it is bounded by chain length and
    // runs once per edit.
    let mut cursor = wc.row(first_id).next_id;
    while cursor != 0 && cursor != last_id {
        tombstone_in_place(wc, cursor);
        cursor = wc.row(cursor).next_id;
    }
    if cursor != last_id {
        return Err(PlannerError::SnapshotInvariant(
            "delete end row not reachable from first row".to_string(),
        ));
    }

    match last {
        LastSpec::Whole(_) => tombstone_in_place(wc, last_id),
        LastSpec::Ragged { row_id, k } => {
            let row = wc.row(row_id).clone();
            ragged_right_within_row(wc, row, k)?;
        }
    }

    Ok(())
}

fn tombstone_in_place(wc: &mut WorkingCopy, row_id: i64) {
    let coord = wc.row(row_id).coord;
    if !coord.tombstone {
        wc.set_coord(
            row_id,
            PieceCoord {
                tombstone: true,
                ..coord
            },
        );
    }
}

fn ragged_left_within_row(wc: &mut WorkingCopy, row: PieceRow, k: u32) -> Result<(), PlannerError> {
    debug_assert!(k > 0 && k < row.coord.len_bytes);
    let s = row.next_id;
    let m_id = wc.alloc_piece_id()?;
    let m_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k,
        len_bytes: row.coord.len_bytes - k,
        tombstone: true,
    };
    wc.insert_new_row(m_id, row.id, s, m_coord)?;
    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k,
        tombstone: row.coord.tombstone,
    };
    wc.set_coord(row.id, new_p_coord);
    wc.set_next(row.id, m_id);
    if s != 0 {
        wc.set_prev(s, m_id);
    } else {
        wc.tail_id = m_id;
    }
    Ok(())
}

fn ragged_right_within_row(
    wc: &mut WorkingCopy,
    row: PieceRow,
    k: u32,
) -> Result<(), PlannerError> {
    debug_assert!(k > 0 && k < row.coord.len_bytes);
    let s = row.next_id;
    let m_id = wc.alloc_piece_id()?;
    let m_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k,
        len_bytes: row.coord.len_bytes - k,
        tombstone: false,
    };
    wc.insert_new_row(m_id, row.id, s, m_coord)?;
    // Original row keeps its left prefix and is tombstoned.
    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k,
        tombstone: true,
    };
    wc.set_coord(row.id, new_p_coord);
    wc.set_next(row.id, m_id);
    if s != 0 {
        wc.set_prev(s, m_id);
    } else {
        wc.tail_id = m_id;
    }
    Ok(())
}

fn ragged_center(
    wc: &mut WorkingCopy,
    row: PieceRow,
    k1: u32,
    k2: u32,
) -> Result<(), PlannerError> {
    debug_assert!(0 < k1 && k1 < k2 && k2 < row.coord.len_bytes);
    let s = row.next_id;
    // Allocate M_deleted first (lower id), then R_right.
    let m_id = wc.alloc_piece_id()?;
    let r_id = wc.alloc_piece_id()?;

    let m_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k1,
        len_bytes: k2 - k1,
        tombstone: true,
    };
    let r_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k2,
        len_bytes: row.coord.len_bytes - k2,
        tombstone: row.coord.tombstone,
    };

    wc.insert_new_row(m_id, row.id, r_id, m_coord)?;
    wc.insert_new_row(r_id, m_id, s, r_coord)?;

    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k1,
        tombstone: row.coord.tombstone,
    };
    wc.set_coord(row.id, new_p_coord);
    wc.set_next(row.id, m_id);
    if s != 0 {
        wc.set_prev(s, r_id);
    } else {
        wc.tail_id = r_id;
    }
    Ok(())
}

#[cfg(test)]
#[path = "piece_text_planner_tests.rs"]
mod tests;
