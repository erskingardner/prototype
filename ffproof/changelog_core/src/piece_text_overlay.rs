//! Indexed overlay edit planner for `_piecetext_pieces` / `_piecetext_buffers`.
//!
//! This is the `OpReader`-backed analogue of the in-memory
//! [`crate::piece_text_planner::WorkingCopy`]. Instead of authenticating the
//! whole `_piecetext_pieces` list for a document up front, it resolves
//! coordinates through the `_piecetext_pieces.buffer_id` secondary index and
//! point-reads only the rows an edit actually touches, while *staging* inserts,
//! row updates, head/tail moves, and next-id bumps in memory so that later ops
//! in the same `PieceTextEdit` observe earlier ones.
//!
//! Stage scope (PLAN_PIECE_SMALL_CLEANUP):
//!
//! * **Stage 1 (this module's initial form):** build [`OverlayPieceStore`] with
//!   the store primitives, the [`ResolveSource`] adapter so the shared
//!   [`crate::piece_text_resolution::resolve_coord_core`] runs against the
//!   overlay, and [`OverlayPieceStore::into_output`] materialisation that emits
//!   the same [`PlannerOutput`] the in-memory planner does.
//! * **Stage 2:** port `Insert` splice planning onto the store inside
//!   [`IndexedPieceEditPlanner::apply_ops`].
//! * **Stage 3:** port `Delete` span planning (resolve start/end through the
//!   shared core, canonicalise endpoints, walk only the affected `next_id`
//!   span, and tombstone/split affected rows) onto the same store.
//! * **Stage 4:** `PieceTextEditOp::extract_and_validate` uses this planner for
//!   production edit verification.

use std::collections::{HashMap, HashSet};

use crate::changelog::ChangelogError;
use crate::ops::OpReader;
use crate::piece_text::{
    BufferCoord, InsertedBufferManifest, PieceCoord, PieceTextAddress, PieceTextEditItemManifest,
    MAX_BUFFER_LEN_BYTES,
};
use crate::piece_text_planner::{
    BufferRowInsert, ClampWalk, IndexLookup, PieceRow, PieceRowInsert, PieceRowUpdate,
    PlannerOutput, PlannerTrace, ResolvePurpose,
};
use crate::piece_text_resolution::{
    resolve_coord_core, ResolveCoreResult, ResolveEndpoint, ResolveSource,
};
use crate::piece_text_resolver::{read_aligned_piece_coords_row, read_candidate_row_ids};

const ERR: &str = "piece_text_overlay";

/// One cached `_piecetext_pieces` row plus its pre-edit values.
///
/// `original_*` are `Some(_)` for a row read from the tree (a pre-existing row,
/// which can produce a [`PieceRowUpdate`]) and `None` for a row staged by
/// [`OverlayPieceStore::insert_new_row`] (which produces a [`PieceRowInsert`]).
#[derive(Debug, Clone)]
struct OverlayRow {
    current: PieceRow,
    original_prev_id: Option<i64>,
    original_next_id: Option<i64>,
    original_coord: Option<PieceCoord>,
}

impl OverlayRow {
    fn is_existing(&self) -> bool {
        self.original_prev_id.is_some()
            || self.original_next_id.is_some()
            || self.original_coord.is_some()
    }
}

/// Authenticated, write-staging view of one document's piece-table state.
///
/// Reads go through the `_piecetext_pieces.buffer_id` index and point keys and
/// are cached; writes are staged and surfaced to later reads in the same edit.
/// [`into_output`](Self::into_output) materialises the staged state into the
/// same [`PlannerOutput`] the in-memory planner emits.
pub struct OverlayPieceStore<'a> {
    reader: &'a mut dyn OpReader,
    list_number: i64,
    author_id: i64,
    address: PieceTextAddress,

    /// Current (possibly staged) chain endpoints, seeded from pre-state.
    head_id: i64,
    tail_id: i64,
    /// Pre-edit chain endpoints, used to decide whether to emit head/tail puts.
    pre_head_id: i64,
    pre_tail_id: i64,

    /// `_piecetext_pieces` next-id counter; bumped by [`alloc_piece_id`].
    next_piece_id: i64,
    /// `_piecetext_buffers` next-id counter; bumped by [`alloc_buffer_id`].
    next_buffer_id: i64,

    /// Loaded + staged piece rows, keyed by row id.
    rows: HashMap<i64, OverlayRow>,
    /// Staged inserts, in allocation order (the verifier assigns sequential
    /// ids from `pre_piece_next_id`, so this order is load-bearing).
    new_piece_ids: Vec<i64>,
    /// Staged new row ids grouped by buffer, merged into candidate lookups.
    new_rows_by_buffer: HashMap<i64, Vec<i64>>,
    /// Cached pre-state `buffer_id` index results, so the index range for a
    /// buffer is authenticated at most once.
    candidate_cache: HashMap<i64, Vec<i64>>,

    /// Staged `_piecetext_buffers` inserts.
    buffer_inserts: Vec<BufferRowInsert>,

    /// Observable index-lookup / clamp-walk trace, for tests and metrics.
    trace: PlannerTrace,
}

impl<'a> OverlayPieceStore<'a> {
    /// Construct a store over `reader` for one document.
    ///
    /// `head_id` / `tail_id` / `pre_piece_next_id` / `pre_buffers_next_id` are
    /// read from the tree by the caller (the `_piecetext_pieces` head/tail keys
    /// and the two table next-id counters) and passed in, mirroring the reads
    /// `PieceTextEditOp::extract_and_validate` already performs. Subsequent
    /// head/tail/next-id state is tracked in-memory so staged writes are
    /// observed by later ops.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: &'a mut dyn OpReader,
        address: PieceTextAddress,
        list_number: i64,
        author_id: i64,
        head_id: i64,
        tail_id: i64,
        pre_piece_next_id: i64,
        pre_buffers_next_id: i64,
    ) -> Result<Self, ChangelogError> {
        if list_number <= 0 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: list_number must be positive, got {list_number}"
            )));
        }
        if pre_piece_next_id < 1 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: pre_piece_next_id must be >= 1, got {pre_piece_next_id}"
            )));
        }
        if pre_buffers_next_id < 1 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: pre_buffers_next_id must be >= 1, got {pre_buffers_next_id}"
            )));
        }
        if head_id < 0 || tail_id < 0 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: head_id/tail_id must be non-negative, got head={head_id} tail={tail_id}"
            )));
        }
        if (head_id == 0) != (tail_id == 0) {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: head_id and tail_id must both be 0 or both be non-zero, got head={head_id} tail={tail_id}"
            )));
        }
        if head_id >= pre_piece_next_id || tail_id >= pre_piece_next_id {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: head_id/tail_id must be < pre_piece_next_id {pre_piece_next_id}, got head={head_id} tail={tail_id}"
            )));
        }

        Ok(Self {
            reader,
            list_number,
            author_id,
            address,
            head_id,
            tail_id,
            pre_head_id: head_id,
            pre_tail_id: tail_id,
            next_piece_id: pre_piece_next_id,
            next_buffer_id: pre_buffers_next_id,
            rows: HashMap::new(),
            new_piece_ids: Vec::new(),
            new_rows_by_buffer: HashMap::new(),
            candidate_cache: HashMap::new(),
            buffer_inserts: Vec::new(),
            trace: PlannerTrace::default(),
        })
    }

    // ---------- reads ----------

    /// Read one piece row, returning its current (staged) value.
    ///
    /// A freshly point-read row is validated (positive id, this document's
    /// `list_number`, non-zero `len_bytes`, UTF-32 alignment, range non-overflow)
    /// and cached so it is authenticated at most once.
    pub fn read_piece_row(&mut self, row_id: i64) -> Result<PieceRow, ChangelogError> {
        self.load_row(row_id)?;
        Ok(self.rows[&row_id].current.clone())
    }

    /// Candidate `_piecetext_pieces` row ids for `buffer_id`: pre-state rows from
    /// the authenticated `buffer_id` index merged with rows staged earlier in
    /// this edit.
    pub fn candidate_row_ids(&mut self, buffer_id: i64) -> Result<Vec<i64>, ChangelogError> {
        if !self.candidate_cache.contains_key(&buffer_id) {
            let pre_state = read_candidate_row_ids(self.reader, buffer_id)?;
            self.candidate_cache.insert(buffer_id, pre_state);
        }
        let mut row_ids = self.candidate_cache[&buffer_id].clone();
        if let Some(staged) = self.new_rows_by_buffer.get(&buffer_id) {
            row_ids.extend_from_slice(staged);
        }
        self.trace.index_lookups.push(IndexLookup {
            buffer_id,
            returned_row_ids: row_ids.clone(),
        });
        Ok(row_ids)
    }

    /// Current (staged) chain head id (0 when the document is empty).
    pub fn read_head(&self) -> i64 {
        self.head_id
    }

    /// Current (staged) chain tail id (0 when the document is empty).
    pub fn read_tail(&self) -> i64 {
        self.tail_id
    }

    /// Upper bound on any valid `_piecetext_pieces` row id: no acyclic chain
    /// can hold more rows than the next-id counter, so chain walks use it as a
    /// cycle-detection cap (a span longer than this implies a malformed loop).
    fn piece_id_ceiling(&self) -> i64 {
        self.next_piece_id
    }

    // ---------- staged writes ----------

    /// Stage a new chain head.
    pub fn set_head(&mut self, head_id: i64) {
        self.head_id = head_id;
    }

    /// Stage a new chain tail.
    pub fn set_tail(&mut self, tail_id: i64) {
        self.tail_id = tail_id;
    }

    /// Stage `row_id.prev_id = prev_id` (loading the row first if needed).
    pub fn set_prev(&mut self, row_id: i64, prev_id: i64) -> Result<(), ChangelogError> {
        self.load_row(row_id)?;
        self.rows.get_mut(&row_id).unwrap().current.prev_id = prev_id;
        Ok(())
    }

    /// Stage `row_id.next_id = next_id` (loading the row first if needed).
    pub fn set_next(&mut self, row_id: i64, next_id: i64) -> Result<(), ChangelogError> {
        self.load_row(row_id)?;
        self.rows.get_mut(&row_id).unwrap().current.next_id = next_id;
        Ok(())
    }

    /// Stage `row_id.coord = coord` (loading the row first if needed).
    pub fn set_coord(&mut self, row_id: i64, coord: PieceCoord) -> Result<(), ChangelogError> {
        self.load_row(row_id)?;
        self.rows.get_mut(&row_id).unwrap().current.coord = coord;
        Ok(())
    }

    /// Stage a brand-new `_piecetext_pieces` row.
    pub fn insert_new_row(
        &mut self,
        id: i64,
        prev_id: i64,
        next_id: i64,
        coord: PieceCoord,
    ) -> Result<(), ChangelogError> {
        if id <= 0 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: inserted row id must be positive, got {id}"
            )));
        }
        if self.rows.contains_key(&id) {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: double-allocated piece row id {id}"
            )));
        }
        let row = PieceRow {
            id,
            list_number: self.list_number,
            prev_id,
            next_id,
            coord,
        };
        self.new_rows_by_buffer
            .entry(coord.buffer_id)
            .or_default()
            .push(id);
        self.new_piece_ids.push(id);
        self.rows.insert(
            id,
            OverlayRow {
                current: row,
                original_prev_id: None,
                original_next_id: None,
                original_coord: None,
            },
        );
        Ok(())
    }

    /// Allocate the next `_piecetext_pieces` row id.
    pub fn alloc_piece_id(&mut self) -> Result<i64, ChangelogError> {
        let id = self.next_piece_id;
        self.next_piece_id = self.next_piece_id.checked_add(1).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{ERR}: _piecetext_pieces next_id counter overflowed i64"
            ))
        })?;
        Ok(id)
    }

    /// Allocate the next `_piecetext_buffers` row id.
    pub fn alloc_buffer_id(&mut self) -> Result<i64, ChangelogError> {
        let id = self.next_buffer_id;
        self.next_buffer_id = self.next_buffer_id.checked_add(1).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{ERR}: _piecetext_buffers next_id counter overflowed i64"
            ))
        })?;
        Ok(id)
    }

    /// Stage a `_piecetext_buffers` insert for an already-allocated `new_id`.
    ///
    /// Owner address and author are taken from the edit; the caller supplies the
    /// inserted buffer's cleartext byte length and contents hash.
    pub fn stage_buffer_insert(
        &mut self,
        new_id: i64,
        len_bytes: u32,
        ciphertext_value_hash: [u8; 32],
    ) {
        self.buffer_inserts.push(BufferRowInsert {
            new_id,
            owner_table: self.address.table.clone(),
            owner_row_id: self.address.row_id,
            owner_column: self.address.column.clone(),
            author_id: self.author_id,
            len_bytes,
            ciphertext_value_hash,
        });
    }

    // ---------- materialisation ----------

    /// Collapse the staged state into the write plan the verifier materialises.
    ///
    /// Matches `piece_text_planner::plan_edit`'s output exactly: inserts in
    /// allocation order, updates sorted by id carrying only changed fields,
    /// head/tail puts only when an endpoint moved, and next-id puts only when a
    /// row was added to the corresponding table.
    pub fn into_output(mut self) -> PlannerOutput {
        let mut authenticated_piece_coords: Vec<(i64, PieceCoord)> = self
            .rows
            .iter()
            .filter_map(|(id, row)| row.original_coord.map(|coord| (*id, coord)))
            .collect();
        authenticated_piece_coords.sort_unstable_by_key(|(id, _)| *id);
        self.trace.authenticated_piece_coords = authenticated_piece_coords;

        let mut piece_inserts: Vec<PieceRowInsert> = Vec::with_capacity(self.new_piece_ids.len());
        for new_id in &self.new_piece_ids {
            let row = &self.rows[new_id].current;
            piece_inserts.push(PieceRowInsert {
                new_id: row.id,
                list_number: row.list_number,
                prev_id: row.prev_id,
                next_id: row.next_id,
                coord: row.coord,
            });
        }

        let mut updated_ids: Vec<i64> = self
            .rows
            .iter()
            .filter_map(|(id, row)| {
                if !row.is_existing() {
                    return None;
                }
                let prev_changed = row.original_prev_id != Some(row.current.prev_id);
                let next_changed = row.original_next_id != Some(row.current.next_id);
                let coord_changed = row.original_coord != Some(row.current.coord);
                (prev_changed || next_changed || coord_changed).then_some(*id)
            })
            .collect();
        updated_ids.sort_unstable();
        let mut piece_updates: Vec<PieceRowUpdate> = Vec::with_capacity(updated_ids.len());
        for id in updated_ids {
            let row = &self.rows[&id];
            let prev_id =
                (row.original_prev_id != Some(row.current.prev_id)).then_some(row.current.prev_id);
            let next_id =
                (row.original_next_id != Some(row.current.next_id)).then_some(row.current.next_id);
            let coord =
                (row.original_coord != Some(row.current.coord)).then_some(row.current.coord);
            piece_updates.push(PieceRowUpdate {
                id,
                prev_id,
                next_id,
                coord,
            });
        }

        let head_update = (self.head_id != self.pre_head_id).then_some(self.head_id);
        let tail_update = (self.tail_id != self.pre_tail_id).then_some(self.tail_id);
        let piece_next_id_post = (!self.new_piece_ids.is_empty()).then_some(self.next_piece_id);
        let buffers_next_id_post = (!self.buffer_inserts.is_empty()).then_some(self.next_buffer_id);

        PlannerOutput {
            piece_inserts,
            piece_updates,
            buffer_inserts: self.buffer_inserts,
            head_update,
            tail_update,
            piece_next_id_post,
            buffers_next_id_post,
            trace: self.trace,
        }
    }

    // ---------- internals ----------

    /// Ensure `row_id` is cached, point-reading and validating it on first use.
    fn load_row(&mut self, row_id: i64) -> Result<(), ChangelogError> {
        if self.rows.contains_key(&row_id) {
            return Ok(());
        }
        // `read_aligned_piece_coords_row` enforces positive id, non-zero
        // len_bytes, range non-overflow, and UTF-32 alignment; bind the row to
        // this document so a `buffer_id`-indexed row from another list cannot be
        // walked into.
        let row = read_aligned_piece_coords_row(self.reader, row_id)?;
        if row.list_number != self.list_number {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: _piecetext_pieces row {row_id} belongs to list {} but this edit targets list {}",
                row.list_number, self.list_number
            )));
        }
        self.rows.insert(
            row_id,
            OverlayRow {
                original_prev_id: Some(row.prev_id),
                original_next_id: Some(row.next_id),
                original_coord: Some(row.coord),
                current: row,
            },
        );
        Ok(())
    }
}

impl ResolveSource for OverlayPieceStore<'_> {
    type Error = ChangelogError;

    fn list_number(&self) -> i64 {
        self.list_number
    }

    fn candidate_row_ids(&mut self, buffer_id: i64) -> Result<Vec<i64>, Self::Error> {
        OverlayPieceStore::candidate_row_ids(self, buffer_id)
    }

    fn read_row(&mut self, row_id: i64) -> Result<PieceRow, Self::Error> {
        self.read_piece_row(row_id)
    }

    fn read_endpoint(&mut self, endpoint: ResolveEndpoint) -> Result<i64, Self::Error> {
        Ok(match endpoint {
            ResolveEndpoint::Head => self.head_id,
            ResolveEndpoint::Tail => self.tail_id,
        })
    }

    fn invalid_coordinate(&self, message: String) -> Self::Error {
        ChangelogError::Generic(format!("{ERR}: {message}"))
    }

    fn unknown_coordinate(
        &self,
        coord: BufferCoord,
        purpose: ResolvePurpose,
        reason: String,
    ) -> Self::Error {
        ChangelogError::Generic(format!(
            "{ERR}: unknown coordinate (buffer_id={}, byte_pos={}, purpose={:?}): {}",
            coord.buffer_id, coord.byte_pos, purpose, reason
        ))
    }

    fn invariant(&self, message: String) -> Self::Error {
        ChangelogError::Generic(format!("{ERR}: {message}"))
    }
}

/// Indexed edit planner: runs a `PieceTextEdit`'s ops against an
/// [`OverlayPieceStore`] and materialises the resulting write plan.
///
/// Both `Insert` splice planning and `Delete` span planning are implemented
/// here against the same overlay, so later ops in one edit observe earlier
/// staged inserts, tombstones, splits, and head/tail moves.
pub struct IndexedPieceEditPlanner<'a> {
    store: OverlayPieceStore<'a>,
    allocated_buffer_ids: HashSet<i64>,
}

impl<'a> IndexedPieceEditPlanner<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: &'a mut dyn OpReader,
        address: PieceTextAddress,
        list_number: i64,
        author_id: i64,
        head_id: i64,
        tail_id: i64,
        pre_piece_next_id: i64,
        pre_buffers_next_id: i64,
    ) -> Result<Self, ChangelogError> {
        Ok(Self {
            store: OverlayPieceStore::new(
                reader,
                address,
                list_number,
                author_id,
                head_id,
                tail_id,
                pre_piece_next_id,
                pre_buffers_next_id,
            )?,
            allocated_buffer_ids: HashSet::new(),
        })
    }

    /// Plan each edit op against the overlay, staging its writes. Later ops
    /// resolve against earlier ops' staged changes. An empty op vector is a
    /// no-op.
    pub fn apply_ops(&mut self, ops: &[PieceTextEditItemManifest]) -> Result<(), ChangelogError> {
        for (i, op) in ops.iter().enumerate() {
            self.apply_op(i, op)?;
        }
        Ok(())
    }

    /// Plan one op against the overlay.
    fn apply_op(
        &mut self,
        index: usize,
        op: &PieceTextEditItemManifest,
    ) -> Result<(), ChangelogError> {
        match op {
            PieceTextEditItemManifest::Insert { at, inserted } => {
                self.apply_insert(index, *at, inserted)
            }
            PieceTextEditItemManifest::Delete { start, end } => {
                self.apply_delete(index, *start, *end)
            }
        }
    }

    fn apply_insert(
        &mut self,
        index: usize,
        at: BufferCoord,
        inserted: &InsertedBufferManifest,
    ) -> Result<(), ChangelogError> {
        if at.buffer_id != 0 && self.allocated_buffer_ids.contains(&at.buffer_id) {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: edit op {index} targets buffer_id {} allocated by an earlier Insert in this same edit",
                at.buffer_id
            )));
        }
        if inserted.len_bytes == 0 {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: Insert.len_bytes must be > 0"
            )));
        }
        if inserted.len_bytes > MAX_BUFFER_LEN_BYTES {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: Insert.len_bytes {} exceeds MAX_BUFFER_LEN_BYTES {MAX_BUFFER_LEN_BYTES}",
                inserted.len_bytes
            )));
        }

        let new_buffer_id = self.store.alloc_buffer_id()?;
        self.allocated_buffer_ids.insert(new_buffer_id);
        self.store.stage_buffer_insert(
            new_buffer_id,
            inserted.len_bytes,
            inserted.ciphertext_value_hash,
        );
        apply_insert_to_store(&mut self.store, at, new_buffer_id, inserted)
    }

    fn apply_delete(
        &mut self,
        index: usize,
        start: BufferCoord,
        end: BufferCoord,
    ) -> Result<(), ChangelogError> {
        // A buffer allocated by an earlier `Insert` in this same edit has no
        // pre-state rows to resolve against, so neither delete endpoint may
        // target it (mirrors the in-memory planner's same-edit guard).
        if start.buffer_id != 0 && self.allocated_buffer_ids.contains(&start.buffer_id) {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: edit op {index} delete start targets buffer_id {} allocated by an earlier Insert in this same edit",
                start.buffer_id
            )));
        }
        if end.buffer_id != 0 && self.allocated_buffer_ids.contains(&end.buffer_id) {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: edit op {index} delete end targets buffer_id {} allocated by an earlier Insert in this same edit",
                end.buffer_id
            )));
        }
        apply_delete_to_store(&mut self.store, start, end)
    }

    /// Borrow the underlying store (used by the splice helpers/tests).
    pub fn store_mut(&mut self) -> &mut OverlayPieceStore<'a> {
        &mut self.store
    }

    /// Materialise the staged edit into a [`PlannerOutput`].
    pub fn into_output(self) -> PlannerOutput {
        self.store.into_output()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OverlayResolveMatch {
    BeforeHead,
    InRow { row: PieceRow, k: u32 },
    AfterClamp { row_id: i64 },
    BeforeHeadClamped,
    AfterTailClamped,
}

fn resolve_overlay_coord(
    store: &mut OverlayPieceStore<'_>,
    coord: BufferCoord,
    purpose: ResolvePurpose,
) -> Result<OverlayResolveMatch, ChangelogError> {
    let output = resolve_coord_core(store, coord, purpose)?;
    record_overlay_clamp_walk(&output.result, purpose, &mut store.trace);

    Ok(match output.result {
        ResolveCoreResult::DocumentStart { .. } => OverlayResolveMatch::BeforeHead,
        ResolveCoreResult::InRow { row, offset } => OverlayResolveMatch::InRow { row, k: offset },
        ResolveCoreResult::ClampedToRow { row, .. } => {
            OverlayResolveMatch::AfterClamp { row_id: row.id }
        }
        ResolveCoreResult::ClampedBeforeHead { .. } => OverlayResolveMatch::BeforeHeadClamped,
        ResolveCoreResult::ClampedAfterTail { .. } => OverlayResolveMatch::AfterTailClamped,
    })
}

fn record_overlay_clamp_walk(
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

fn apply_insert_to_store(
    store: &mut OverlayPieceStore<'_>,
    at: BufferCoord,
    new_buffer_id: i64,
    inserted: &InsertedBufferManifest,
) -> Result<(), ChangelogError> {
    let resolution = resolve_overlay_coord(store, at, ResolvePurpose::InsertAnchor)?;
    let splice = derive_insert_splice(store, resolution, at)?;
    let new_coord = PieceCoord {
        buffer_id: new_buffer_id,
        start_byte: 0,
        len_bytes: inserted.len_bytes,
        tombstone: false,
    };

    match splice {
        InsertSplice::AtHead => {
            let new_id = store.alloc_piece_id()?;
            let old_head = store.read_head();
            if old_head != 0 {
                let head = store.read_piece_row(old_head)?;
                if head.prev_id != 0 {
                    return Err(ChangelogError::Generic(format!(
                        "{ERR}: head row {old_head} has non-zero prev_id {}",
                        head.prev_id
                    )));
                }
            }
            store.insert_new_row(new_id, 0, old_head, new_coord)?;
            if old_head != 0 {
                store.set_prev(old_head, new_id)?;
            }
            store.set_head(new_id);
            if store.read_tail() == 0 {
                store.set_tail(new_id);
            }
        }
        InsertSplice::AfterRow { id: anchor_id } => {
            let anchor = store.read_piece_row(anchor_id)?;
            let s = anchor.next_id;
            if s != 0 {
                let successor = store.read_piece_row(s)?;
                if successor.prev_id != anchor_id {
                    return Err(ChangelogError::Generic(format!(
                        "{ERR}: row {s}.prev_id={} but expected {anchor_id}",
                        successor.prev_id
                    )));
                }
            } else if anchor_id != store.read_tail() {
                return Err(ChangelogError::Generic(format!(
                    "{ERR}: row {anchor_id} has next_id 0 but is not tail {}",
                    store.read_tail()
                )));
            }

            let new_id = store.alloc_piece_id()?;
            store.insert_new_row(new_id, anchor_id, s, new_coord)?;
            store.set_next(anchor_id, new_id)?;
            if s != 0 {
                store.set_prev(s, new_id)?;
            } else {
                store.set_tail(new_id);
            }
        }
        InsertSplice::SplitRow { row: p, k } => {
            let s = p.next_id;
            if s != 0 {
                let successor = store.read_piece_row(s)?;
                if successor.prev_id != p.id {
                    return Err(ChangelogError::Generic(format!(
                        "{ERR}: row {s}.prev_id={} but expected {}",
                        successor.prev_id, p.id
                    )));
                }
            } else if p.id != store.read_tail() {
                return Err(ChangelogError::Generic(format!(
                    "{ERR}: row {} has next_id 0 but is not tail {}",
                    p.id,
                    store.read_tail()
                )));
            }

            let n_id = store.alloc_piece_id()?;
            let r_id = store.alloc_piece_id()?;
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

            store.set_coord(p.id, new_p_coord)?;
            store.insert_new_row(n_id, p.id, r_id, new_coord)?;
            store.insert_new_row(r_id, n_id, s, r_coord)?;
            store.set_next(p.id, n_id)?;
            if s != 0 {
                store.set_prev(s, r_id)?;
            } else {
                store.set_tail(r_id);
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InsertSplice {
    AtHead,
    AfterRow { id: i64 },
    SplitRow { row: PieceRow, k: u32 },
}

fn derive_insert_splice(
    store: &mut OverlayPieceStore<'_>,
    resolution: OverlayResolveMatch,
    at: BufferCoord,
) -> Result<InsertSplice, ChangelogError> {
    match resolution {
        OverlayResolveMatch::BeforeHead | OverlayResolveMatch::BeforeHeadClamped => {
            Ok(InsertSplice::AtHead)
        }
        OverlayResolveMatch::AfterTailClamped => Err(ChangelogError::Generic(format!(
            "{ERR}: insert at {at:?} forward-clamped past tail; InsertAnchor should back-clamp"
        ))),
        OverlayResolveMatch::AfterClamp { row_id } => Ok(InsertSplice::AfterRow { id: row_id }),
        OverlayResolveMatch::InRow { row, k } => {
            if k == row.coord.len_bytes {
                Ok(InsertSplice::AfterRow { id: row.id })
            } else if k == 0 {
                if row.prev_id == 0 {
                    if row.id != store.read_head() {
                        return Err(ChangelogError::Generic(format!(
                            "{ERR}: row {} has prev_id 0 but is not head {}",
                            row.id,
                            store.read_head()
                        )));
                    }
                    Ok(InsertSplice::AtHead)
                } else {
                    let prev = store.read_piece_row(row.prev_id)?;
                    if prev.next_id != row.id {
                        return Err(ChangelogError::Generic(format!(
                            "{ERR}: row {}.next_id={} but expected {}",
                            prev.id, prev.next_id, row.id
                        )));
                    }
                    Ok(InsertSplice::AfterRow { id: row.prev_id })
                }
            } else {
                Ok(InsertSplice::SplitRow { row, k })
            }
        }
    }
}

// ---------- delete ----------

/// Canonical, totally-ordered delete position over the overlay chain.
///
/// Mirrors `piece_text_planner::DeletePos`: `BeforeHead` < every `InRow` <
/// `AfterTail`, with `k` kept strictly inside `(0, row.len_bytes]` so that two
/// coords mapping to the same rendered byte gap canonicalise to structurally
/// equal positions (§4.1 "predecessor side wins").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeletePos {
    BeforeHead,
    InRow { row_id: i64, k: u32 },
    AfterTail,
}

fn apply_delete_to_store(
    store: &mut OverlayPieceStore<'_>,
    start: BufferCoord,
    end: BufferCoord,
) -> Result<(), ChangelogError> {
    let start = resolve_delete_start(store, start)?;
    let end = resolve_delete_end(store, end)?;
    use std::cmp::Ordering;
    match compare_positions(store, start, end)? {
        Ordering::Equal => Ok(()),
        Ordering::Greater => Err(ChangelogError::Generic(format!(
            "{ERR}: delete start resolved past delete end"
        ))),
        Ordering::Less => execute_delete(store, start, end),
    }
}

fn resolve_delete_start(
    store: &mut OverlayPieceStore<'_>,
    coord: BufferCoord,
) -> Result<DeletePos, ChangelogError> {
    let resolution = resolve_overlay_coord(store, coord, ResolvePurpose::DeleteStart)?;
    Ok(match resolution {
        OverlayResolveMatch::BeforeHead => DeletePos::BeforeHead,
        OverlayResolveMatch::AfterTailClamped => DeletePos::AfterTail,
        OverlayResolveMatch::AfterClamp { row_id } => canonicalize_in_row(store, row_id, 0)?,
        OverlayResolveMatch::InRow { row, k } => canonicalize_in_row(store, row.id, k)?,
        OverlayResolveMatch::BeforeHeadClamped => {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: DeleteStart should never produce a backward clamp result"
            )))
        }
    })
}

fn resolve_delete_end(
    store: &mut OverlayPieceStore<'_>,
    coord: BufferCoord,
) -> Result<DeletePos, ChangelogError> {
    let resolution = resolve_overlay_coord(store, coord, ResolvePurpose::DeleteEnd)?;
    Ok(match resolution {
        OverlayResolveMatch::BeforeHead | OverlayResolveMatch::BeforeHeadClamped => {
            DeletePos::BeforeHead
        }
        OverlayResolveMatch::AfterClamp { row_id } => {
            // Backward clamp landed on a live row; the delete end sits at that
            // row's right edge (§4.1), so canonicalise from there.
            let len = store.read_piece_row(row_id)?.coord.len_bytes;
            canonicalize_in_row(store, row_id, len)?
        }
        OverlayResolveMatch::InRow { row, k } => canonicalize_in_row(store, row.id, k)?,
        OverlayResolveMatch::AfterTailClamped => {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: DeleteEnd should never produce a forward clamp result"
            )))
        }
    })
}

/// Canonicalise a `(row_id, k)` anchor (a live row from the resolver, with
/// `k ∈ [0, row.len_bytes]`) into a [`DeletePos`].
///
/// `k == 0` ("left edge") walks back over tombstones to the live predecessor's
/// right edge, or `BeforeHead` when none exists. `k == row.len_bytes` ("right
/// edge") collapses to `AfterTail` only when no live successor exists; otherwise
/// it stays as the canonical "after this row" position.
fn canonicalize_in_row(
    store: &mut OverlayPieceStore<'_>,
    row_id: i64,
    k: u32,
) -> Result<DeletePos, ChangelogError> {
    let row = store.read_piece_row(row_id)?;
    if k == 0 {
        let cap = store.piece_id_ceiling();
        let mut cur = row;
        let mut hops = 0i64;
        loop {
            match step_backward(store, &cur)? {
                None => return Ok(DeletePos::BeforeHead),
                Some(prev) => {
                    if !prev.coord.tombstone {
                        return Ok(DeletePos::InRow {
                            row_id: prev.id,
                            k: prev.coord.len_bytes,
                        });
                    }
                    cur = prev;
                }
            }
            hops += 1;
            if hops > cap {
                return Err(ChangelogError::Generic(format!(
                    "{ERR}: delete canonicalisation walk exceeded document length"
                )));
            }
        }
    }
    if k == row.coord.len_bytes {
        let cap = store.piece_id_ceiling();
        let mut cur = row;
        let mut hops = 0i64;
        loop {
            match step_forward(store, &cur)? {
                None => return Ok(DeletePos::AfterTail),
                Some(next) => {
                    if !next.coord.tombstone {
                        return Ok(DeletePos::InRow { row_id, k });
                    }
                    cur = next;
                }
            }
            hops += 1;
            if hops > cap {
                return Err(ChangelogError::Generic(format!(
                    "{ERR}: delete canonicalisation walk exceeded document length"
                )));
            }
        }
    }
    Ok(DeletePos::InRow { row_id, k })
}

/// Read the chain successor of `row`, validating pointer symmetry and binding a
/// 0 `next_id` to the staged tail. Returns `None` at the tail.
///
/// Re-establishes locally the doubly-linked invariant the in-memory planner gets
/// from full-snapshot validation, exactly as the resolver's clamp walk does.
fn step_forward(
    store: &mut OverlayPieceStore<'_>,
    row: &PieceRow,
) -> Result<Option<PieceRow>, ChangelogError> {
    if row.next_id == 0 {
        let tail = store.read_tail();
        if row.id != tail {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: row {} has next_id 0 but is not tail {tail}",
                row.id
            )));
        }
        return Ok(None);
    }
    let next = store.read_piece_row(row.next_id)?;
    if next.prev_id != row.id {
        return Err(ChangelogError::Generic(format!(
            "{ERR}: row {}.prev_id={} but expected {}",
            next.id, next.prev_id, row.id
        )));
    }
    Ok(Some(next))
}

/// Read the chain predecessor of `row`, validating pointer symmetry and binding
/// a 0 `prev_id` to the staged head. Returns `None` at the head.
fn step_backward(
    store: &mut OverlayPieceStore<'_>,
    row: &PieceRow,
) -> Result<Option<PieceRow>, ChangelogError> {
    if row.prev_id == 0 {
        let head = store.read_head();
        if row.id != head {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: row {} has prev_id 0 but is not head {head}",
                row.id
            )));
        }
        return Ok(None);
    }
    let prev = store.read_piece_row(row.prev_id)?;
    if prev.next_id != row.id {
        return Err(ChangelogError::Generic(format!(
            "{ERR}: row {}.next_id={} but expected {}",
            prev.id, prev.next_id, row.id
        )));
    }
    Ok(Some(prev))
}

fn compare_positions(
    store: &mut OverlayPieceStore<'_>,
    a: DeletePos,
    b: DeletePos,
) -> Result<std::cmp::Ordering, ChangelogError> {
    use std::cmp::Ordering;
    // In an empty or all-tombstoned chain there is no live content, so
    // `BeforeHead` and `AfterTail` collapse to the same rendered byte gap and
    // such a pair is a no-op, not an inverted delete. Only walk for the first
    // live row when both endpoints are chain extremes: an `InRow` endpoint
    // already proves live content exists, and walking the leading tombstone run
    // for an interior delete would touch rows outside the affected span.
    let both_extremes = matches!(a, DeletePos::BeforeHead | DeletePos::AfterTail)
        && matches!(b, DeletePos::BeforeHead | DeletePos::AfterTail);
    if both_extremes && first_live_row(store)?.is_none() {
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
            } else if chain_walk_lt(store, r1, r2)? {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    })
}

/// Whether `a_id` precedes `b_id` in chain order, by walking forward from
/// `a_id`. In a valid (non-inverted) delete this only walks the affected span;
/// an inverted delete walks to the tail without finding `b_id` and returns
/// false, surfacing as the "start past end" rejection upstream.
fn chain_walk_lt(
    store: &mut OverlayPieceStore<'_>,
    a_id: i64,
    b_id: i64,
) -> Result<bool, ChangelogError> {
    if a_id == b_id {
        return Ok(false);
    }
    let cap = store.piece_id_ceiling();
    let mut cur = store.read_piece_row(a_id)?;
    let mut hops = 0i64;
    loop {
        match step_forward(store, &cur)? {
            None => return Ok(false),
            Some(next) => {
                if next.id == b_id {
                    return Ok(true);
                }
                cur = next;
            }
        }
        hops += 1;
        if hops > cap {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: delete order walk exceeded document length"
            )));
        }
    }
}

/// First live row walking forward from the staged head, or `None` if the chain
/// is empty or entirely tombstoned.
fn first_live_row(store: &mut OverlayPieceStore<'_>) -> Result<Option<i64>, ChangelogError> {
    let head = store.read_head();
    if head == 0 {
        return Ok(None);
    }
    let cap = store.piece_id_ceiling();
    let mut cur = store.read_piece_row(head)?;
    if cur.prev_id != 0 {
        return Err(ChangelogError::Generic(format!(
            "{ERR}: head row {head} has non-zero prev_id {}",
            cur.prev_id
        )));
    }
    let mut hops = 0i64;
    loop {
        if !cur.coord.tombstone {
            return Ok(Some(cur.id));
        }
        match step_forward(store, &cur)? {
            None => return Ok(None),
            Some(next) => cur = next,
        }
        hops += 1;
        if hops > cap {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: first-live-row walk exceeded document length"
            )));
        }
    }
}

/// Last live row walking backward from the staged tail, or `None` if the chain
/// is empty or entirely tombstoned.
fn last_live_row(store: &mut OverlayPieceStore<'_>) -> Result<Option<i64>, ChangelogError> {
    let tail = store.read_tail();
    if tail == 0 {
        return Ok(None);
    }
    let cap = store.piece_id_ceiling();
    let mut cur = store.read_piece_row(tail)?;
    if cur.next_id != 0 {
        return Err(ChangelogError::Generic(format!(
            "{ERR}: tail row {tail} has non-zero next_id {}",
            cur.next_id
        )));
    }
    let mut hops = 0i64;
    loop {
        if !cur.coord.tombstone {
            return Ok(Some(cur.id));
        }
        match step_backward(store, &cur)? {
            None => return Ok(None),
            Some(prev) => cur = prev,
        }
        hops += 1;
        if hops > cap {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: last-live-row walk exceeded document length"
            )));
        }
    }
}

/// First live row strictly after `row_id` in chain order, or `None` if every
/// successor is tombstoned (or `row_id` is the tail).
fn next_live_row(
    store: &mut OverlayPieceStore<'_>,
    row_id: i64,
) -> Result<Option<i64>, ChangelogError> {
    let cap = store.piece_id_ceiling();
    let mut cur = store.read_piece_row(row_id)?;
    let mut hops = 0i64;
    loop {
        match step_forward(store, &cur)? {
            None => return Ok(None),
            Some(next) => {
                if !next.coord.tombstone {
                    return Ok(Some(next.id));
                }
                cur = next;
            }
        }
        hops += 1;
        if hops > cap {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: next-live-row walk exceeded document length"
            )));
        }
    }
}

/// Action on the first affected row of a delete (or the only row of a
/// single-row delete).
#[derive(Debug, Clone, Copy)]
enum FirstSpec {
    /// Whole row falls in range. `Some(id)` when there is a live row to act on;
    /// `None` when the start has no live successor.
    Whole(Option<i64>),
    /// Ragged-left cut at offset `k`.
    Ragged { row_id: i64, k: u32 },
}

#[derive(Debug, Clone, Copy)]
enum LastSpec {
    /// Whole row falls in range.
    Whole(Option<i64>),
    /// Ragged-right cut at offset `k`.
    Ragged { row_id: i64, k: u32 },
}

fn execute_delete(
    store: &mut OverlayPieceStore<'_>,
    start: DeletePos,
    end: DeletePos,
) -> Result<(), ChangelogError> {
    let first = match start {
        DeletePos::BeforeHead => FirstSpec::Whole(first_live_row(store)?),
        DeletePos::InRow { row_id, k } => {
            let row_len = store.read_piece_row(row_id)?.coord.len_bytes;
            if k == row_len {
                // Right edge of `row_id`: the row itself is not deleted; the
                // first affected row is the next live row (canonical form
                // guarantees one exists).
                FirstSpec::Whole(next_live_row(store, row_id)?)
            } else {
                FirstSpec::Ragged { row_id, k }
            }
        }
        DeletePos::AfterTail => return Ok(()),
    };
    let last = match end {
        DeletePos::AfterTail => LastSpec::Whole(last_live_row(store)?),
        DeletePos::InRow { row_id, k } => {
            let row_len = store.read_piece_row(row_id)?.coord.len_bytes;
            if k == row_len {
                LastSpec::Whole(Some(row_id))
            } else {
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
        let row = store.read_piece_row(first_id)?;
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
            tombstone_in_place(store, first_id)?;
        } else if k1 == 0 {
            ragged_right_within_row(store, row, k2)?;
        } else if k2 == row.coord.len_bytes {
            ragged_left_within_row(store, row, k1)?;
        } else {
            ragged_center(store, row, k1, k2)?;
        }
        return Ok(());
    }

    // Multi-row case: cut/tombstone the first row, tombstone every interior row
    // along the affected span, then cut/tombstone the last row.
    match first {
        FirstSpec::Whole(_) => tombstone_in_place(store, first_id)?,
        FirstSpec::Ragged { row_id, k } => {
            let row = store.read_piece_row(row_id)?;
            ragged_left_within_row(store, row, k)?;
        }
    }

    // Interior tombstone walk: proportional to the rows between first and last,
    // i.e. the affected span. Tombstoning never rewrites `next` pointers, so the
    // chain stays stable; `first_id` is re-read because a ragged-left cut moved
    // its `next_id` to the freshly inserted tombstone remainder.
    let cap = store.piece_id_ceiling();
    let mut cur = store.read_piece_row(first_id)?;
    let mut hops = 0i64;
    loop {
        match step_forward(store, &cur)? {
            None => {
                return Err(ChangelogError::Generic(format!(
                    "{ERR}: delete end row not reachable from first row"
                )))
            }
            Some(next) => {
                if next.id == last_id {
                    break;
                }
                tombstone_in_place(store, next.id)?;
                cur = next;
            }
        }
        hops += 1;
        if hops > cap {
            return Err(ChangelogError::Generic(format!(
                "{ERR}: delete interior walk exceeded document length"
            )));
        }
    }

    match last {
        LastSpec::Whole(_) => tombstone_in_place(store, last_id)?,
        LastSpec::Ragged { row_id, k } => {
            let row = store.read_piece_row(row_id)?;
            ragged_right_within_row(store, row, k)?;
        }
    }

    Ok(())
}

fn tombstone_in_place(
    store: &mut OverlayPieceStore<'_>,
    row_id: i64,
) -> Result<(), ChangelogError> {
    let coord = store.read_piece_row(row_id)?.coord;
    if !coord.tombstone {
        store.set_coord(
            row_id,
            PieceCoord {
                tombstone: true,
                ..coord
            },
        )?;
    }
    Ok(())
}

fn ragged_left_within_row(
    store: &mut OverlayPieceStore<'_>,
    row: PieceRow,
    k: u32,
) -> Result<(), ChangelogError> {
    debug_assert!(k > 0 && k < row.coord.len_bytes);
    let s = row.next_id;
    // Validate the successor pointer before repointing it (the same symmetry
    // check the insert splice helpers run).
    let successor = step_forward(store, &row)?;
    let m_id = store.alloc_piece_id()?;
    let m_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k,
        len_bytes: row.coord.len_bytes - k,
        tombstone: true,
    };
    store.insert_new_row(m_id, row.id, s, m_coord)?;
    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k,
        tombstone: row.coord.tombstone,
    };
    store.set_coord(row.id, new_p_coord)?;
    store.set_next(row.id, m_id)?;
    if successor.is_some() {
        store.set_prev(s, m_id)?;
    } else {
        store.set_tail(m_id);
    }
    Ok(())
}

fn ragged_right_within_row(
    store: &mut OverlayPieceStore<'_>,
    row: PieceRow,
    k: u32,
) -> Result<(), ChangelogError> {
    debug_assert!(k > 0 && k < row.coord.len_bytes);
    let s = row.next_id;
    let successor = step_forward(store, &row)?;
    let m_id = store.alloc_piece_id()?;
    let m_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte + k,
        len_bytes: row.coord.len_bytes - k,
        tombstone: false,
    };
    store.insert_new_row(m_id, row.id, s, m_coord)?;
    // Original row keeps its left prefix and is tombstoned.
    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k,
        tombstone: true,
    };
    store.set_coord(row.id, new_p_coord)?;
    store.set_next(row.id, m_id)?;
    if successor.is_some() {
        store.set_prev(s, m_id)?;
    } else {
        store.set_tail(m_id);
    }
    Ok(())
}

fn ragged_center(
    store: &mut OverlayPieceStore<'_>,
    row: PieceRow,
    k1: u32,
    k2: u32,
) -> Result<(), ChangelogError> {
    debug_assert!(0 < k1 && k1 < k2 && k2 < row.coord.len_bytes);
    let s = row.next_id;
    let successor = step_forward(store, &row)?;
    // Allocate M_deleted first (lower id), then R_right.
    let m_id = store.alloc_piece_id()?;
    let r_id = store.alloc_piece_id()?;
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
    store.insert_new_row(m_id, row.id, r_id, m_coord)?;
    store.insert_new_row(r_id, m_id, s, r_coord)?;
    let new_p_coord = PieceCoord {
        buffer_id: row.coord.buffer_id,
        start_byte: row.coord.start_byte,
        len_bytes: k1,
        tombstone: row.coord.tombstone,
    };
    store.set_coord(row.id, new_p_coord)?;
    store.set_next(row.id, m_id)?;
    if successor.is_some() {
        store.set_prev(s, r_id)?;
    } else {
        store.set_tail(r_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piece_text_resolution::resolve_coord_core;
    use crate::{ProvenRead, ReadOp};
    use encrypted_spaces_storage_encoding::keys::{
        column_key, index_key, piece_coords_head_key, piece_coords_tail_key, row_id_to_bytes,
        PIECE_COORDS_TABLE,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use ffproof_tracer_shared::prefix_successor;
    use serde_json::json;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use crate::piece_text_planner::ClampDirection;
    use crate::piece_text_resolver::{
        PIECE_COORDS_COL_BUFFER_ID, PIECE_COORDS_COL_LEN_BYTES, PIECE_COORDS_COL_LIST_NUMBER,
        PIECE_COORDS_COL_NEXT_ID, PIECE_COORDS_COL_PREV_ID, PIECE_COORDS_COL_START_BYTE,
        PIECE_COORDS_COL_TOMBSTONE,
    };

    const LIST: i64 = 5;

    /// `OverlayPieceStore` holds the reader as `&mut dyn OpReader`, so the read
    /// log can't be reached back through the trait object. Share it via an
    /// `Rc<RefCell<_>>` the test clones before constructing the store.
    type ReadLog = Rc<RefCell<Vec<ReadOp>>>;

    #[derive(Default)]
    struct StubReader {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        reads: ReadLog,
    }

    impl StubReader {
        fn reads_handle(&self) -> ReadLog {
            Rc::clone(&self.reads)
        }

        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.kv.insert(key, value);
        }

        fn put_row(&mut self, row: &PieceRow) {
            for (col, val) in [
                (PIECE_COORDS_COL_LIST_NUMBER, row.list_number),
                (PIECE_COORDS_COL_PREV_ID, row.prev_id),
                (PIECE_COORDS_COL_NEXT_ID, row.next_id),
                (PIECE_COORDS_COL_BUFFER_ID, row.coord.buffer_id),
                (PIECE_COORDS_COL_START_BYTE, row.coord.start_byte as i64),
                (PIECE_COORDS_COL_LEN_BYTES, row.coord.len_bytes as i64),
                (
                    PIECE_COORDS_COL_TOMBSTONE,
                    if row.coord.tombstone { 1 } else { 0 },
                ),
            ] {
                self.put(column_key(PIECE_COORDS_TABLE, row.id, col), stored_i64(val));
            }
            self.put(
                index_key(
                    PIECE_COORDS_TABLE,
                    PIECE_COORDS_COL_BUFFER_ID,
                    row.coord.buffer_id,
                    row.id,
                )
                .unwrap(),
                row_id_to_bytes(row.id).to_vec(),
            );
        }
    }

    impl OpReader for StubReader {
        fn read(&mut self, op: ReadOp) -> Result<ProvenRead, ChangelogError> {
            self.reads.borrow_mut().push(op.clone());
            let results = match &op {
                ReadOp::Key(key) => self
                    .kv
                    .get(key)
                    .map(|v| vec![(key.clone(), v.clone())])
                    .unwrap_or_default(),
                ReadOp::Range { start, end } => self
                    .kv
                    .range(start.clone()..end.clone())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                ReadOp::Prefix(prefix) => match prefix_successor(prefix) {
                    Some(end) => self
                        .kv
                        .range(prefix.clone()..end)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    None => self
                        .kv
                        .range(prefix.clone()..)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                },
            };
            Ok(ProvenRead { op, results })
        }
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&json!(value)).unwrap()
    }

    fn coord(buffer_id: i64, start_byte: u32, len_bytes: u32, tombstone: bool) -> PieceCoord {
        PieceCoord {
            buffer_id,
            start_byte,
            len_bytes,
            tombstone,
        }
    }

    fn inserted(len_bytes: u32, marker: u8) -> InsertedBufferManifest {
        InsertedBufferManifest {
            len_bytes,
            ciphertext_len: len_bytes + 16,
            ciphertext_value_hash: [marker; 32],
        }
    }

    fn row(id: i64, prev_id: i64, next_id: i64, c: PieceCoord) -> PieceRow {
        PieceRow {
            id,
            list_number: LIST,
            prev_id,
            next_id,
            coord: c,
        }
    }

    fn address() -> PieceTextAddress {
        PieceTextAddress {
            table: "docs".to_string(),
            row_id: 42,
            column: "body".to_string(),
        }
    }

    /// Seed a two-row, single-buffer document: head(1) -> tail(2), buffer 7
    /// spanning [0, 16). Returns a ready reader with head/tail keys set.
    fn two_row_doc() -> StubReader {
        let mut reader = StubReader::default();
        reader.put_row(&row(1, 0, 2, coord(7, 0, 8, false)));
        reader.put_row(&row(2, 1, 0, coord(7, 8, 8, false)));
        reader.put(piece_coords_head_key(LIST), 1i64.to_be_bytes().to_vec());
        reader.put(piece_coords_tail_key(LIST), 2i64.to_be_bytes().to_vec());
        reader
    }

    fn store(reader: &mut StubReader) -> OverlayPieceStore<'_> {
        // pre_piece_next_id = 3 (rows 1,2 live), pre_buffers_next_id = 8.
        OverlayPieceStore::new(reader, address(), LIST, 99, 1, 2, 3, 8).unwrap()
    }

    fn one_piece_doc() -> StubReader {
        let mut reader = StubReader::default();
        reader.put_row(&row(10, 0, 0, coord(5, 0, 8, false)));
        reader.put(piece_coords_head_key(LIST), 10i64.to_be_bytes().to_vec());
        reader.put(piece_coords_tail_key(LIST), 10i64.to_be_bytes().to_vec());
        reader
    }

    fn bc(buffer_id: i64, byte_pos: u32) -> BufferCoord {
        BufferCoord {
            buffer_id,
            byte_pos,
        }
    }

    fn delete_item(start: BufferCoord, end: BufferCoord) -> PieceTextEditItemManifest {
        PieceTextEditItemManifest::Delete { start, end }
    }

    /// Seed a `StubReader` from a row list (each row's columns + `buffer_id`
    /// index entry). Head/tail/next-ids are passed to the planner constructor,
    /// so only the rows themselves need to live in the reader.
    fn doc(rows: &[PieceRow]) -> StubReader {
        let mut reader = StubReader::default();
        for r in rows {
            reader.put_row(r);
        }
        reader
    }

    /// Assert a planned edit staged no writes (a no-op). Compares only the
    /// write batch; the resolver still records its read trace, so a full
    /// `PlannerOutput::default()` equality would not hold.
    fn assert_no_writes(out: &PlannerOutput) {
        assert!(out.piece_inserts.is_empty(), "{out:?}");
        assert!(out.piece_updates.is_empty(), "{out:?}");
        assert!(out.buffer_inserts.is_empty(), "{out:?}");
        assert_eq!(out.head_update, None);
        assert_eq!(out.tail_update, None);
        assert_eq!(out.piece_next_id_post, None);
        assert_eq!(out.buffers_next_id_post, None);
    }

    /// Single live piece, buffer 5 spanning `[0, 12)` (4-byte aligned), used by
    /// the single-row ragged-delete tests. Row reads enforce UTF-32 alignment,
    /// so every coord here is a multiple of 4.
    fn wide_one_piece_doc() -> StubReader {
        doc(&[row(10, 0, 0, coord(5, 0, 12, false))])
    }

    /// `A(buf 1, [0,4)) -> B(buf 2, [0,4)) -> C(buf 3, [0,4))`, all live and
    /// aligned; the overlay twin of the planner's three-piece fixture.
    fn three_piece_doc() -> StubReader {
        doc(&[
            row(1, 0, 2, coord(1, 0, 4, false)),
            row(2, 1, 3, coord(2, 0, 4, false)),
            row(3, 2, 0, coord(3, 0, 4, false)),
        ])
    }

    #[test]
    fn new_rejects_inconsistent_endpoints_and_counters() {
        let mut reader = StubReader::default();
        // head set, tail zero.
        assert!(OverlayPieceStore::new(&mut reader, address(), LIST, 1, 1, 0, 3, 8).is_err());
        // head id beyond pre_piece_next_id.
        assert!(OverlayPieceStore::new(&mut reader, address(), LIST, 1, 9, 2, 3, 8).is_err());
        // next-id below 1.
        assert!(OverlayPieceStore::new(&mut reader, address(), LIST, 1, 0, 0, 0, 8).is_err());
        // non-positive list_number.
        assert!(OverlayPieceStore::new(&mut reader, address(), 0, 1, 0, 0, 3, 8).is_err());
        // valid empty document.
        assert!(OverlayPieceStore::new(&mut reader, address(), LIST, 1, 0, 0, 1, 1).is_ok());
    }

    #[test]
    fn read_piece_row_point_reads_and_caches() {
        let mut reader = two_row_doc();
        let log = reader.reads_handle();
        let mut s = store(&mut reader);
        let got = s.read_piece_row(2).unwrap();
        assert_eq!(got, row(2, 1, 0, coord(7, 8, 8, false)));
        let reads_after_first = log.borrow().len();
        assert!(reads_after_first > 0);
        // Second read of the same row must not re-authenticate any keys.
        let again = s.read_piece_row(2).unwrap();
        assert_eq!(again, got);
        assert_eq!(log.borrow().len(), reads_after_first);
    }

    #[test]
    fn read_piece_row_rejects_row_from_other_document() {
        let mut reader = StubReader::default();
        let mut foreign = row(1, 0, 0, coord(7, 0, 8, false));
        foreign.list_number = LIST + 1;
        reader.put_row(&foreign);
        let mut s = OverlayPieceStore::new(&mut reader, address(), LIST, 1, 0, 0, 2, 8).unwrap();
        let err = s.read_piece_row(1).unwrap_err().to_string();
        assert!(err.contains("belongs to list"), "{err}");
    }

    #[test]
    fn clamp_rejects_zero_prev_pointer_that_is_not_head() {
        // The overlay adapter must enforce the same endpoint binding as the
        // resolver: a tombstone reached via the buffer_id index whose prev_id is
        // 0 but which is not the seeded head must be rejected, not mis-clamped to
        // document start. Without this the indexed path would lose an invariant
        // the full-snapshot planner used to enforce by whole-list validation.
        let mut reader = StubReader::default();
        // Row 2 is a tombstone claiming to be head (prev_id 0); head is row 1.
        reader.put_row(&row(2, 0, 0, coord(7, 0, 8, true)));
        reader.put(piece_coords_head_key(LIST), 1i64.to_be_bytes().to_vec());
        reader.put(piece_coords_tail_key(LIST), 2i64.to_be_bytes().to_vec());
        // head=1, tail=2, pre_piece_next_id=3 so the seeded endpoints validate.
        let mut s = OverlayPieceStore::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        let err = resolve_coord_core(
            &mut s,
            BufferCoord {
                buffer_id: 7,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not the document head"), "{err}");
    }

    #[test]
    fn candidate_row_ids_merges_prestate_with_staged_and_caches_index() {
        let mut reader = two_row_doc();
        let log = reader.reads_handle();
        let mut s = store(&mut reader);
        assert_eq!(s.candidate_row_ids(7).unwrap(), vec![1, 2]);
        let reads_after_first = log.borrow().len();

        // Stage a new row in buffer 7; candidate lookup must include it without
        // re-reading the buffer_id index range.
        let new_id = s.alloc_piece_id().unwrap();
        assert_eq!(new_id, 3);
        s.insert_new_row(new_id, 0, 1, coord(7, 0, 4, false))
            .unwrap();
        assert_eq!(s.candidate_row_ids(7).unwrap(), vec![1, 2, 3]);
        assert_eq!(log.borrow().len(), reads_after_first);

        // The trace records both lookups (logical lookups, even on cache hit).
        assert_eq!(s.trace.index_lookups.len(), 2);
        assert_eq!(s.trace.index_lookups[1].returned_row_ids, vec![1, 2, 3]);
    }

    #[test]
    fn resolve_coord_core_runs_over_overlay_via_indexed_reads() {
        let mut reader = two_row_doc();
        let log = reader.reads_handle();
        let mut s = store(&mut reader);
        // byte_pos 8 sits at the boundary of rows 1 and 2: predecessor (row 1)
        // wins per the shared core's tie-break.
        let out = resolve_coord_core(
            &mut s,
            BufferCoord {
                buffer_id: 7,
                byte_pos: 8,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap();
        assert_eq!(out.candidate_count, 2);
        // Every read issued was a point Key read or a buffer_id index Range —
        // never a list_number range scan over the whole document.
        let list_prefix = encrypted_spaces_storage_encoding::keys::index_value_prefix(
            PIECE_COORDS_TABLE,
            PIECE_COORDS_COL_LIST_NUMBER,
            LIST,
        )
        .unwrap();
        assert!(log.borrow().iter().all(|op| match op {
            ReadOp::Key(_) => true,
            ReadOp::Range { start, .. } => !start.starts_with(&list_prefix),
            ReadOp::Prefix(p) => !p.starts_with(&list_prefix),
        }));
    }

    #[test]
    fn staged_updates_and_inserts_materialise_like_plan_edit() {
        let mut reader = two_row_doc();
        let mut s = store(&mut reader);

        // Splice a new row between 1 and 2: new id 3, prev 1, next 2.
        let new_id = s.alloc_piece_id().unwrap();
        s.insert_new_row(new_id, 1, 2, coord(7, 0, 4, false))
            .unwrap();
        s.set_next(1, new_id).unwrap();
        s.set_prev(2, new_id).unwrap();

        let out = s.into_output();

        assert_eq!(out.piece_inserts.len(), 1);
        assert_eq!(out.piece_inserts[0].new_id, 3);
        assert_eq!(out.piece_inserts[0].prev_id, 1);
        assert_eq!(out.piece_inserts[0].next_id, 2);

        // Two existing rows changed exactly one pointer each, sorted by id, and
        // only the changed field is carried.
        assert_eq!(out.piece_updates.len(), 2);
        assert_eq!(out.piece_updates[0].id, 1);
        assert_eq!(out.piece_updates[0].next_id, Some(3));
        assert_eq!(out.piece_updates[0].prev_id, None);
        assert_eq!(out.piece_updates[0].coord, None);
        assert_eq!(out.piece_updates[1].id, 2);
        assert_eq!(out.piece_updates[1].prev_id, Some(3));
        assert_eq!(out.piece_updates[1].next_id, None);

        // A row added => piece next-id post; no head/tail move, no buffers.
        assert_eq!(out.piece_next_id_post, Some(4));
        assert_eq!(out.head_update, None);
        assert_eq!(out.tail_update, None);
        assert!(out.buffer_inserts.is_empty());
        assert_eq!(out.buffers_next_id_post, None);
    }

    #[test]
    fn head_tail_and_buffer_inserts_materialise() {
        let mut reader = two_row_doc();
        let mut s = store(&mut reader);

        // Prepend a new head in a freshly inserted buffer.
        let buf_id = s.alloc_buffer_id().unwrap();
        assert_eq!(buf_id, 8);
        s.stage_buffer_insert(buf_id, 4, [0xAB; 32]);
        let new_id = s.alloc_piece_id().unwrap();
        s.insert_new_row(new_id, 0, 1, coord(buf_id, 0, 4, false))
            .unwrap();
        s.set_prev(1, new_id).unwrap();
        s.set_head(new_id);

        let out = s.into_output();
        assert_eq!(out.head_update, Some(3));
        assert_eq!(out.tail_update, None);
        assert_eq!(out.buffer_inserts.len(), 1);
        assert_eq!(out.buffer_inserts[0].new_id, 8);
        assert_eq!(out.buffer_inserts[0].owner_table, "docs");
        assert_eq!(out.buffer_inserts[0].author_id, 99);
        assert_eq!(out.buffers_next_id_post, Some(9));
        assert_eq!(out.piece_next_id_post, Some(4));
    }

    #[test]
    fn set_coord_tombstone_and_set_tail_materialise() {
        let mut reader = two_row_doc();
        let mut s = store(&mut reader);

        // Tombstone the tail row in place (coord update), then append a new live
        // row after it and move the tail forward.
        s.set_coord(2, coord(7, 8, 8, true)).unwrap();
        let buf_id = s.alloc_buffer_id().unwrap();
        s.stage_buffer_insert(buf_id, 4, [0xCD; 32]);
        let new_id = s.alloc_piece_id().unwrap();
        s.insert_new_row(new_id, 2, 0, coord(buf_id, 0, 4, false))
            .unwrap();
        s.set_next(2, new_id).unwrap();
        s.set_tail(new_id);

        let out = s.into_output();

        // Row 2 changed both its coord (now tombstoned) and its next pointer.
        assert_eq!(out.piece_updates.len(), 1);
        let upd = &out.piece_updates[0];
        assert_eq!(upd.id, 2);
        assert_eq!(upd.next_id, Some(3));
        assert_eq!(upd.prev_id, None);
        assert_eq!(upd.coord, Some(coord(7, 8, 8, true)));

        assert_eq!(out.tail_update, Some(3));
        assert_eq!(out.head_update, None);
        assert_eq!(out.piece_inserts.len(), 1);
        assert_eq!(out.buffer_inserts.len(), 1);
    }

    #[test]
    fn no_op_edit_materialises_empty_output() {
        let mut reader = two_row_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        planner.apply_ops(&[]).unwrap();
        let out = planner.into_output();
        assert_eq!(out, PlannerOutput::default());
    }

    #[test]
    fn indexed_insert_empty_insert_into_empty_document() {
        let mut reader = StubReader::default();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 0, 0, 1, 1).unwrap();
        planner
            .apply_ops(&[PieceTextEditItemManifest::Insert {
                at: BufferCoord::DOCUMENT_START,
                inserted: inserted(4, 0xAA),
            }])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 1);
        let n = &out.piece_inserts[0];
        assert_eq!(n.new_id, 1);
        assert_eq!(n.prev_id, 0);
        assert_eq!(n.next_id, 0);
        assert_eq!(n.coord, coord(1, 0, 4, false));
        assert_eq!(out.buffer_inserts.len(), 1);
        assert_eq!(out.buffer_inserts[0].new_id, 1);
        assert_eq!(out.buffer_inserts[0].ciphertext_value_hash, [0xAA; 32]);
        assert_eq!(out.head_update, Some(1));
        assert_eq!(out.tail_update, Some(1));
        assert_eq!(out.piece_next_id_post, Some(2));
        assert_eq!(out.buffers_next_id_post, Some(2));
    }

    #[test]
    fn indexed_insert_append_after_existing_piece() {
        let mut reader = one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[PieceTextEditItemManifest::Insert {
                at: BufferCoord {
                    buffer_id: 5,
                    byte_pos: 8,
                },
                inserted: inserted(4, 0xBB),
            }])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 1);
        let n = &out.piece_inserts[0];
        assert_eq!(n.new_id, 11);
        assert_eq!(n.prev_id, 10);
        assert_eq!(n.next_id, 0);
        assert_eq!(n.coord, coord(6, 0, 4, false));
        assert_eq!(out.piece_updates.len(), 1);
        assert_eq!(out.piece_updates[0].id, 10);
        assert_eq!(out.piece_updates[0].next_id, Some(11));
        assert_eq!(out.piece_updates[0].prev_id, None);
        assert_eq!(out.piece_updates[0].coord, None);
        assert_eq!(out.head_update, None);
        assert_eq!(out.tail_update, Some(11));
    }

    #[test]
    fn indexed_insert_split_inside_a_piece() {
        let mut reader = one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[PieceTextEditItemManifest::Insert {
                at: BufferCoord {
                    buffer_id: 5,
                    byte_pos: 4,
                },
                inserted: inserted(4, 0xCC),
            }])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 2);
        let n = &out.piece_inserts[0];
        let r = &out.piece_inserts[1];
        assert_eq!(n.new_id, 11);
        assert_eq!(n.prev_id, 10);
        assert_eq!(n.next_id, 12);
        assert_eq!(n.coord, coord(6, 0, 4, false));
        assert_eq!(r.new_id, 12);
        assert_eq!(r.prev_id, 11);
        assert_eq!(r.next_id, 0);
        assert_eq!(r.coord, coord(5, 4, 4, false));

        assert_eq!(out.piece_updates.len(), 1);
        let update = &out.piece_updates[0];
        assert_eq!(update.id, 10);
        assert_eq!(update.next_id, Some(11));
        assert_eq!(update.coord, Some(coord(5, 0, 4, false)));
        assert_eq!(out.tail_update, Some(12));
        assert_eq!(out.piece_next_id_post, Some(13));
    }

    #[test]
    fn indexed_insert_same_coordinate_inserts_render_newest_first() {
        let mut reader = StubReader::default();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 0, 0, 1, 1).unwrap();
        planner
            .apply_ops(&[
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord::DOCUMENT_START,
                    inserted: inserted(4, 0x01),
                },
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord::DOCUMENT_START,
                    inserted: inserted(4, 0x02),
                },
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord::DOCUMENT_START,
                    inserted: inserted(4, 0x03),
                },
            ])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 3);
        let t1 = &out.piece_inserts[0];
        let t2 = &out.piece_inserts[1];
        let t3 = &out.piece_inserts[2];
        assert_eq!(t1.new_id, 1);
        assert_eq!(t2.new_id, 2);
        assert_eq!(t3.new_id, 3);
        assert_eq!(t3.prev_id, 0);
        assert_eq!(t3.next_id, 2);
        assert_eq!(t2.prev_id, 3);
        assert_eq!(t2.next_id, 1);
        assert_eq!(t1.prev_id, 2);
        assert_eq!(t1.next_id, 0);
        assert_eq!(out.head_update, Some(3));
        assert_eq!(out.tail_update, Some(1));
    }

    #[test]
    fn indexed_insert_inside_tombstone_back_clamps_to_live_predecessor() {
        let mut reader = StubReader::default();
        reader.put_row(&row(1, 0, 2, coord(5, 0, 4, false)));
        reader.put_row(&row(2, 1, 3, coord(5, 4, 4, true)));
        reader.put_row(&row(3, 2, 0, coord(5, 8, 4, false)));
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 3, 4, 6).unwrap();
        planner
            .apply_ops(&[PieceTextEditItemManifest::Insert {
                at: BufferCoord {
                    buffer_id: 5,
                    byte_pos: 8,
                },
                inserted: inserted(4, 0xDD),
            }])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.trace.clamp_walks.len(), 1);
        let walk = &out.trace.clamp_walks[0];
        assert_eq!(walk.start_row_id, 2);
        assert_eq!(walk.direction, ClampDirection::Backward);
        assert_eq!(walk.purpose, ResolvePurpose::InsertAnchor);
        assert_eq!(walk.hops, 1);
        assert_eq!(walk.end_row_id, Some(1));

        let n = &out.piece_inserts[0];
        assert_eq!(n.prev_id, 1);
        assert_eq!(n.next_id, 2);
        assert_eq!(out.piece_updates[0].id, 1);
        assert_eq!(out.piece_updates[0].next_id, Some(4));
        assert_eq!(out.piece_updates[1].id, 2);
        assert_eq!(out.piece_updates[1].prev_id, Some(4));
    }

    #[test]
    fn indexed_insert_after_row_changed_earlier_in_same_edit() {
        let mut reader = one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord {
                        buffer_id: 5,
                        byte_pos: 4,
                    },
                    inserted: inserted(4, 0x11),
                },
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord {
                        buffer_id: 5,
                        byte_pos: 4,
                    },
                    inserted: inserted(4, 0x22),
                },
            ])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 3);
        assert_eq!(out.piece_inserts[0].new_id, 11);
        assert_eq!(out.piece_inserts[0].prev_id, 13);
        assert_eq!(out.piece_inserts[0].next_id, 12);
        assert_eq!(out.piece_inserts[1].new_id, 12);
        assert_eq!(out.piece_inserts[1].prev_id, 11);
        assert_eq!(out.piece_inserts[1].next_id, 0);
        let second_insert = &out.piece_inserts[2];
        assert_eq!(second_insert.new_id, 13);
        assert_eq!(second_insert.prev_id, 10);
        assert_eq!(second_insert.next_id, 11);
        assert_eq!(second_insert.coord.buffer_id, 7);

        assert_eq!(out.piece_updates.len(), 1);
        let p = &out.piece_updates[0];
        assert_eq!(p.id, 10);
        assert_eq!(p.next_id, Some(13));
        assert_eq!(p.coord, Some(coord(5, 0, 4, false)));
        assert_eq!(out.tail_update, Some(12));
        assert_eq!(out.piece_next_id_post, Some(14));
        assert_eq!(out.buffers_next_id_post, Some(8));
    }

    #[test]
    fn indexed_insert_rejects_coord_targeting_buffer_allocated_in_same_edit() {
        let mut reader = StubReader::default();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 0, 0, 1, 1).unwrap();
        let err = planner
            .apply_ops(&[
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord::DOCUMENT_START,
                    inserted: inserted(4, 0x01),
                },
                PieceTextEditItemManifest::Insert {
                    at: BufferCoord {
                        buffer_id: 1,
                        byte_pos: 4,
                    },
                    inserted: inserted(4, 0x02),
                },
            ])
            .unwrap_err()
            .to_string();
        assert!(err.contains("allocated by an earlier Insert"), "{err}");
    }

    #[test]
    fn indexed_insert_rejects_overlapping_candidate_rows_for_buffer() {
        let mut reader = StubReader::default();
        reader.put_row(&row(1, 0, 2, coord(5, 0, 8, false)));
        reader.put_row(&row(2, 1, 0, coord(5, 4, 8, false)));
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 6).unwrap();
        let err = planner
            .apply_ops(&[PieceTextEditItemManifest::Insert {
                at: BufferCoord {
                    buffer_id: 5,
                    byte_pos: 4,
                },
                inserted: inserted(4, 0x33),
            }])
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlap for buffer_id 5"), "{err}");
    }

    #[test]
    fn insert_new_row_rejects_double_allocation() {
        let mut reader = two_row_doc();
        let mut s = store(&mut reader);
        s.insert_new_row(3, 0, 1, coord(7, 0, 4, false)).unwrap();
        let err = s
            .insert_new_row(3, 0, 1, coord(7, 0, 4, false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("double-allocated"), "{err}");
    }

    #[test]
    fn indexed_delete_whole_piece_only_flips_tombstone() {
        // Delete exactly B's range out of A -> B -> C; B is tombstoned in place
        // with no inserts and no adjacency changes.
        let mut reader = three_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 3, 4, 4).unwrap();
        planner
            .apply_ops(&[delete_item(bc(2, 0), bc(2, 4))])
            .unwrap();
        let out = planner.into_output();

        assert!(out.piece_inserts.is_empty());
        assert!(out.buffer_inserts.is_empty());
        assert_eq!(out.piece_updates.len(), 1);
        let upd = &out.piece_updates[0];
        assert_eq!(upd.id, 2);
        assert!(upd.prev_id.is_none());
        assert!(upd.next_id.is_none());
        assert_eq!(upd.coord, Some(coord(2, 0, 4, true)));
        assert_eq!(out.piece_next_id_post, None);
        assert_eq!(out.buffers_next_id_post, None);
        assert_eq!(out.head_update, None);
        assert_eq!(out.tail_update, None);
    }

    #[test]
    fn indexed_delete_ragged_center_within_one_piece() {
        // Buffer 5 [0,12). Delete [4,8): M_deleted (id 11) then R_right (id 12),
        // P shrinks to len 4.
        let mut reader = wide_one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[delete_item(bc(5, 4), bc(5, 8))])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 2);
        let m = &out.piece_inserts[0];
        let r = &out.piece_inserts[1];
        assert_eq!(m.new_id, 11);
        assert_eq!(r.new_id, 12);
        assert_eq!(m.coord, coord(5, 4, 4, true));
        assert_eq!(m.prev_id, 10);
        assert_eq!(m.next_id, 12);
        assert_eq!(r.coord, coord(5, 8, 4, false));
        assert_eq!(r.prev_id, 11);
        assert_eq!(r.next_id, 0);

        assert_eq!(out.piece_updates.len(), 1);
        let p = &out.piece_updates[0];
        assert_eq!(p.id, 10);
        assert_eq!(p.next_id, Some(11));
        assert_eq!(p.coord, Some(coord(5, 0, 4, false)));
        assert_eq!(out.tail_update, Some(12));
        assert_eq!(out.head_update, None);
        assert_eq!(out.piece_next_id_post, Some(13));
    }

    #[test]
    fn indexed_delete_ragged_left_within_one_piece() {
        // Buffer 5 [0,12). Delete [4,12): right suffix becomes one tombstone.
        let mut reader = wide_one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[delete_item(bc(5, 4), bc(5, 12))])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 1);
        let m = &out.piece_inserts[0];
        assert_eq!(m.new_id, 11);
        assert_eq!(m.coord, coord(5, 4, 8, true));
        assert_eq!(m.prev_id, 10);
        assert_eq!(m.next_id, 0);

        assert_eq!(out.piece_updates.len(), 1);
        let p = &out.piece_updates[0];
        assert_eq!(p.id, 10);
        assert_eq!(p.next_id, Some(11));
        assert_eq!(p.coord, Some(coord(5, 0, 4, false)));
        assert_eq!(out.tail_update, Some(11));
        assert_eq!(out.head_update, None);
    }

    #[test]
    fn indexed_delete_ragged_right_within_one_piece() {
        // Buffer 5 [0,12). Delete [0,8): left prefix tombstoned, right kept.
        let mut reader = wide_one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[delete_item(bc(5, 0), bc(5, 8))])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 1);
        let m = &out.piece_inserts[0];
        assert_eq!(m.coord, coord(5, 8, 4, false));
        assert_eq!(m.prev_id, 10);
        assert_eq!(m.next_id, 0);

        assert_eq!(out.piece_updates.len(), 1);
        let p = &out.piece_updates[0];
        assert_eq!(p.id, 10);
        assert_eq!(p.next_id, Some(11));
        assert_eq!(p.coord, Some(coord(5, 0, 8, true)));
        assert_eq!(out.tail_update, Some(11));
        assert_eq!(out.head_update, None);
    }

    #[test]
    fn indexed_delete_across_multiple_pieces() {
        // A(buf1 [0,8)) -> B(buf2 [0,4)) -> C(buf3 [0,8)). Delete from middle of
        // A (byte 4) to middle of C (byte 4): ML_deleted then MR_right, B
        // tombstoned in place. Mirrors the planner's both-ragged ordering test.
        let mut reader = doc(&[
            row(1, 0, 2, coord(1, 0, 8, false)),
            row(2, 1, 3, coord(2, 0, 4, false)),
            row(3, 2, 0, coord(3, 0, 8, false)),
        ]);
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 3, 4, 4).unwrap();
        planner
            .apply_ops(&[delete_item(bc(1, 4), bc(3, 4))])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 2);
        let ml = &out.piece_inserts[0];
        let mr = &out.piece_inserts[1];
        assert_eq!(ml.new_id, 4);
        assert_eq!(mr.new_id, 5);
        assert_eq!(ml.coord, coord(1, 4, 4, true));
        assert_eq!(ml.prev_id, 1);
        assert_eq!(ml.next_id, 2);
        assert_eq!(mr.coord, coord(3, 4, 4, false));
        assert_eq!(mr.prev_id, 3);
        assert_eq!(mr.next_id, 0);

        let updates: HashMap<i64, &PieceRowUpdate> =
            out.piece_updates.iter().map(|u| (u.id, u)).collect();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[&1].next_id, Some(4));
        assert_eq!(updates[&1].coord, Some(coord(1, 0, 4, false)));
        assert!(updates[&1].prev_id.is_none());
        assert_eq!(updates[&2].prev_id, Some(4));
        assert_eq!(updates[&2].coord, Some(coord(2, 0, 4, true)));
        assert!(updates[&2].next_id.is_none());
        assert_eq!(updates[&3].next_id, Some(5));
        assert_eq!(updates[&3].coord, Some(coord(3, 0, 4, true)));
        assert!(updates[&3].prev_id.is_none());

        assert_eq!(out.tail_update, Some(5));
        assert_eq!(out.head_update, None);
        assert_eq!(out.piece_next_id_post, Some(6));
    }

    #[test]
    fn indexed_delete_start_end_clamp_through_tombstone_runs() {
        // A(buf1 [0,8), tomb) -> B(buf2 [0,4), live) -> C(buf3 [0,8), tomb).
        // Delete from inside tombstoned A to inside tombstoned C: DeleteStart
        // forward-clamps onto B, DeleteEnd backward-clamps onto B, so only B is
        // tombstoned. The trace records both clamp directions.
        let mut reader = doc(&[
            row(1, 0, 2, coord(1, 0, 8, true)),
            row(2, 1, 3, coord(2, 0, 4, false)),
            row(3, 2, 0, coord(3, 0, 8, true)),
        ]);
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 3, 4, 4).unwrap();
        planner
            .apply_ops(&[delete_item(bc(1, 4), bc(3, 4))])
            .unwrap();
        let out = planner.into_output();

        let forward: Vec<_> = out
            .trace
            .clamp_walks
            .iter()
            .filter(|w| w.direction == ClampDirection::Forward)
            .collect();
        let backward: Vec<_> = out
            .trace
            .clamp_walks
            .iter()
            .filter(|w| w.direction == ClampDirection::Backward)
            .collect();
        assert_eq!(forward.len(), 1);
        assert_eq!(forward[0].purpose, ResolvePurpose::DeleteStart);
        assert_eq!(forward[0].end_row_id, Some(2));
        assert_eq!(backward.len(), 1);
        assert_eq!(backward[0].purpose, ResolvePurpose::DeleteEnd);
        assert_eq!(backward[0].end_row_id, Some(2));

        assert!(out.piece_inserts.is_empty());
        assert_eq!(out.piece_updates.len(), 1);
        assert_eq!(out.piece_updates[0].id, 2);
        assert_eq!(out.piece_updates[0].coord, Some(coord(2, 0, 4, true)));
    }

    #[test]
    fn indexed_delete_inside_all_tombstoned_chain_is_noop() {
        // Every row already tombstoned: DeleteStart clamps to AfterTail,
        // DeleteEnd clamps to BeforeHead, and the all-tombstoned chain makes
        // those compare equal -> a no-op, not an inverted delete.
        let mut reader = doc(&[
            row(1, 0, 2, coord(5, 0, 8, true)),
            row(2, 1, 0, coord(5, 8, 8, true)),
        ]);
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 6).unwrap();
        planner
            .apply_ops(&[delete_item(bc(5, 4), bc(5, 12))])
            .unwrap();
        let out = planner.into_output();
        assert_no_writes(&out);
    }

    #[test]
    fn indexed_delete_zero_width_at_inter_row_boundary_is_noop() {
        // Collapsed range exactly on the boundary between rows 1 and 2.
        let mut reader = two_row_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        planner
            .apply_ops(&[delete_item(bc(7, 8), bc(7, 8))])
            .unwrap();
        let out = planner.into_output();
        assert_no_writes(&out);
    }

    #[test]
    fn indexed_delete_at_document_start_collapsed_is_noop() {
        // DOCUMENT_START..DOCUMENT_START resolves BeforeHead..BeforeHead.
        let mut reader = two_row_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        planner
            .apply_ops(&[delete_item(
                BufferCoord::DOCUMENT_START,
                BufferCoord::DOCUMENT_START,
            )])
            .unwrap();
        let out = planner.into_output();
        assert_no_writes(&out);
    }

    #[test]
    fn indexed_delete_rejects_inverted_range() {
        // Start inside row 2, end inside row 1: start resolves past end.
        let mut reader = two_row_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        let err = planner
            .apply_ops(&[delete_item(bc(7, 12), bc(7, 4))])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("delete start resolved past delete end"),
            "{err}"
        );
    }

    #[test]
    fn indexed_delete_then_insert_at_deleted_boundary() {
        // Buffer 5 [0,12). Delete [4,8) (P=10, M_deleted=11, R_right=12), then
        // insert at byte 4: the new row N (id 13) splices after P, before
        // M_deleted, so the chain becomes P -> N -> M_deleted -> R_right.
        let mut reader = wide_one_piece_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 10, 10, 11, 6).unwrap();
        planner
            .apply_ops(&[
                delete_item(bc(5, 4), bc(5, 8)),
                PieceTextEditItemManifest::Insert {
                    at: bc(5, 4),
                    inserted: inserted(4, 0xFE),
                },
            ])
            .unwrap();
        let out = planner.into_output();

        assert_eq!(out.piece_inserts.len(), 3);
        assert_eq!(out.piece_inserts[0].new_id, 11);
        assert_eq!(out.piece_inserts[1].new_id, 12);
        assert_eq!(out.piece_inserts[2].new_id, 13);

        // N spliced after P (10), before M_deleted (11), in the freshly
        // allocated buffer 6.
        let n = &out.piece_inserts[2];
        assert_eq!(n.prev_id, 10);
        assert_eq!(n.next_id, 11);
        assert_eq!(n.coord.buffer_id, 6);
        assert_eq!(n.coord.len_bytes, 4);

        // M_deleted is a new row, so its rewired prev_id (now N=13) shows up in
        // its insert payload, not as an update.
        assert_eq!(out.piece_inserts[0].prev_id, 13);
        assert_eq!(out.piece_inserts[0].next_id, 12);
        assert_eq!(out.piece_inserts[1].prev_id, 11);
        assert_eq!(out.piece_inserts[1].next_id, 0);

        let p = out
            .piece_updates
            .iter()
            .find(|u| u.id == 10)
            .expect("update for P");
        assert_eq!(p.next_id, Some(13));
        assert_eq!(p.coord, Some(coord(5, 0, 4, false)));
        assert_eq!(out.tail_update, Some(12));
        assert_eq!(out.head_update, None);
    }

    #[test]
    fn indexed_delete_overlapping_sequential_deletes_idempotent_in_overlap() {
        // A(buf1 [0,8)) -> B(buf2 [0,4)) -> C(buf3 [0,8)). First delete A
        // entirely; second delete runs from inside the now-tombstoned A to the
        // middle of C. A must tombstone exactly once, B is wholly tombstoned, C
        // is ragged-right.
        let mut reader = doc(&[
            row(1, 0, 2, coord(1, 0, 8, false)),
            row(2, 1, 3, coord(2, 0, 4, false)),
            row(3, 2, 0, coord(3, 0, 8, false)),
        ]);
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 3, 4, 4).unwrap();
        planner
            .apply_ops(&[
                delete_item(bc(1, 0), bc(1, 8)),
                delete_item(bc(1, 4), bc(3, 4)),
            ])
            .unwrap();
        let out = planner.into_output();

        let forward: Vec<_> = out
            .trace
            .clamp_walks
            .iter()
            .filter(|w| w.direction == ClampDirection::Forward)
            .collect();
        assert!(!forward.is_empty());
        assert_eq!(forward[0].purpose, ResolvePurpose::DeleteStart);
        assert_eq!(forward[0].hops, 1);
        assert_eq!(forward[0].end_row_id, Some(2));

        let updates: HashMap<i64, &PieceRowUpdate> =
            out.piece_updates.iter().map(|u| (u.id, u)).collect();
        // A tombstoned exactly once (single coord update, not double-flipped).
        assert_eq!(updates[&1].coord, Some(coord(1, 0, 8, true)));
        // B wholly tombstoned.
        assert!(updates[&2].coord.unwrap().tombstone);

        // C ragged-right: one new live suffix row.
        assert_eq!(out.piece_inserts.len(), 1);
        let mr = &out.piece_inserts[0];
        assert_eq!(mr.coord, coord(3, 4, 4, false));
    }

    #[test]
    fn store_mut_exposes_primitives_through_planner() {
        let mut reader = two_row_doc();
        let mut planner =
            IndexedPieceEditPlanner::new(&mut reader, address(), LIST, 99, 1, 2, 3, 8).unwrap();
        let head = planner.store_mut().read_head();
        assert_eq!(head, 1);
        assert_eq!(planner.store_mut().read_tail(), 2);
    }
}
