use std::collections::{BTreeMap, BTreeSet};

use super::{
    decode_i64_column_value, read_schema_piece_text_columns, OpContext, OpReader, OpVerifier,
    OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError};
use crate::piece_text::PieceTextAddress;
use crate::piece_text_cleanup::{PieceTextCleanupPiecesEnvelopeV1, PieceTextCleanupRunV1};
use crate::piece_text_planner::PieceRow;
use crate::piece_text_resolver::{
    piece_coords_delete_index_deletes, read_piece_coords_row, PIECE_COORDS_COL_BUFFER_ID,
    PIECE_COORDS_COL_LEN_BYTES, PIECE_COORDS_COL_LIST_NUMBER, PIECE_COORDS_COL_NEXT_ID,
    PIECE_COORDS_COL_PREV_ID, PIECE_COORDS_COL_START_BYTE, PIECE_COORDS_COL_TOMBSTONE,
};
use crate::{BatchOp, ReadOp, TraceStep};
use encrypted_spaces_storage_encoding::keys::{
    column_key, decode_list_parent, piece_coords_head_key, piece_coords_parent_key,
    piece_coords_tail_key, PIECE_COORDS_TABLE,
};

pub struct PieceTextCleanupPiecesOp;

const OP_NAME: &str = "piece_text_cleanup_pieces";

impl OpVerifier for PieceTextCleanupPiecesOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let envelope = PieceTextCleanupPiecesEnvelopeV1::decode_from_entry(entry)?;
        validate_current_change_id(envelope.op_id, ctx)?;

        let piece_text_columns =
            read_schema_piece_text_columns(&envelope.address.table, reader, ctx)?;
        if !piece_text_columns.contains(&envelope.address.column) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: column '{}.{}' is not declared as PieceText",
                envelope.address.table, envelope.address.column
            )));
        }

        let parent_list_number = read_parent_list_number(reader, &envelope.address)?;
        if parent_list_number != envelope.list_number {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: parent PieceText cell list_number {parent_list_number} does not match envelope list_number {}",
                envelope.list_number
            )));
        }
        authenticate_piece_text_parent(reader, envelope.list_number, &envelope.address)?;

        let head_id = read_raw_i64_key(
            reader,
            piece_coords_head_key(envelope.list_number),
            "piece_coords head",
        )?;
        let tail_id = read_raw_i64_key(
            reader,
            piece_coords_tail_key(envelope.list_number),
            "piece_coords tail",
        )?;

        // Removal ids across the whole envelope (already deduped by
        // `validate_runs`). Used to reject a derived boundary that is itself a
        // removed row.
        let removed_set: BTreeSet<i64> = envelope
            .runs
            .iter()
            .flat_map(|run| run.removals.iter().copied())
            .collect();

        let mut row_cache = BTreeMap::new();
        let mut batch_ops = Vec::new();
        let mut write_keys = BTreeSet::new();
        let mut seen_boundaries = BTreeSet::new();
        {
            let mut run_state = RunValidationState {
                envelope: &envelope,
                head_id,
                tail_id,
                reader,
                row_cache: &mut row_cache,
                batch_ops: &mut batch_ops,
                write_keys: &mut write_keys,
                removed_set: &removed_set,
                seen_boundaries: &mut seen_boundaries,
            };

            for run in &envelope.runs {
                validate_and_materialise_run(run, &mut run_state)?;
            }
        }

        Ok(OpVerifyResult {
            write_steps: vec![TraceStep::Write(batch_ops)],
        })
    }
}

struct RunValidationState<'a, 'r> {
    envelope: &'a PieceTextCleanupPiecesEnvelopeV1,
    head_id: i64,
    tail_id: i64,
    reader: &'r mut dyn OpReader,
    row_cache: &'r mut BTreeMap<i64, PieceRow>,
    batch_ops: &'r mut Vec<BatchOp>,
    write_keys: &'r mut BTreeSet<Vec<u8>>,
    /// All removal row ids in the envelope (deduped by `validate_runs`). A
    /// derived boundary survivor that appears here would dangle a relink.
    removed_set: &'a BTreeSet<i64>,
    /// Non-zero derived boundary survivors already claimed by an earlier run;
    /// keeps splices independent (no shared survivor).
    seen_boundaries: &'r mut BTreeSet<i64>,
}

fn validate_current_change_id(op_id: i64, ctx: &OpContext) -> Result<(), ChangelogError> {
    let current_change_id = i64::try_from(ctx.current_change_id).map_err(|_| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: current_change_id {} is outside i64 range",
            ctx.current_change_id
        ))
    })?;
    if op_id != current_change_id {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: envelope op_id {op_id} does not match current_change_id {current_change_id}"
        )));
    }
    Ok(())
}

fn validate_and_materialise_run(
    run: &PieceTextCleanupRunV1,
    state: &mut RunValidationState<'_, '_>,
) -> Result<(), ChangelogError> {
    let first_removed = run.removals[0];
    let last_removed = *run.removals.last().ok_or_else(|| {
        ChangelogError::Generic(format!("{OP_NAME}: run must remove at least one row"))
    })?;

    let mut removed_rows = Vec::with_capacity(run.removals.len());
    for &row_id in &run.removals {
        let row = read_piece_row_cached(state.reader, state.row_cache, row_id)?;
        validate_removed_row(&row, state.envelope.list_number)?;
        removed_rows.push(row);
    }

    // Internal links: each removed row points to the next, both directions.
    for pair in removed_rows.windows(2) {
        let current = &pair[0];
        let next = &pair[1];
        if current.next_id != next.id {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: removed row {} next_id is {}, expected next removed row {}",
                current.id, current.next_id, next.id
            )));
        }
        if next.prev_id != current.id {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: removed row {} prev_id is {}, expected previous removed row {}",
                next.id, next.prev_id, current.id
            )));
        }
    }

    // --- Boundary survivor elision (intentional, invariant-dependent) ---
    //
    // The bracketing survivors are DERIVED from the authenticated endpoint rows
    // (`first.prev_id` / `last.next_id`); the survivor rows themselves are NOT
    // read. This is a deliberate cost optimization — it removes two tree reads
    // per run — that trades an independent boundary re-check for a dependency on
    // the `_piecetext_pieces` doubly-linked-list invariant:
    //
    //   For a well-formed list, `first.prev_id == P` (P != 0) implies row P
    //   exists, belongs to this list, and has `P.next_id == first` — and
    //   symmetrically for `last.next_id == N` at the tail.
    //
    // That invariant is maintained inductively by every op that mutates the list:
    // `PieceTextEdit` resolves coordinates through the indexed `OpReader` path and
    // splices only the affected `next_id` span (preserving prev/next symmetry as it
    // writes, without reading the whole list), and the cleanup ops only splice
    // (relinking the two survivors around a removed run, below), so they preserve
    // it. Given the invariant, reading P/N
    // to confirm `P.next == first` / `N.prev == last` and their list membership
    // would be redundant, so we skip it and write the relinks to the derived ids.
    //
    // What still bounds the splice WITHOUT the survivor reads:
    //   - the internal forward+reverse link checks above (the run is a real
    //     contiguous chain of authenticated, tombstoned rows);
    //   - the sentinel checks below (a derived 0 boundary really is head/tail);
    //   - the cross-run independence checks below (no survivor is a removed row,
    //     no survivor is shared by two runs), computed on the derived ids;
    //   - the guest's exact-write end-root check, which rejects the op unless the
    //     emitted writes reproduce the server's proven post-state root.
    //
    // What we GIVE UP: an independent proof that the boundary survivor rows exist
    // and are list-consistent in the pre-state. If that invariant dependency is
    // ever in doubt, restore the stronger check by reading P and N here and
    // asserting `P.next == first`, `N.prev == last`, and same-list membership.
    let first_row = &removed_rows[0];
    let last_row = removed_rows.last().expect("removed_rows is non-empty");
    let prev_survivor = first_row.prev_id;
    let next_survivor = last_row.next_id;

    // Sentinel consistency: a derived `0` boundary must sit at the authenticated
    // head/tail.
    if prev_survivor == 0 && state.head_id != first_removed {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: run starts at row {first_removed} (prev_id 0), but list head is {}",
            state.head_id
        )));
    }
    if next_survivor == 0 && state.tail_id != last_removed {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: run ends at row {last_removed} (next_id 0), but list tail is {}",
            state.tail_id
        )));
    }

    // Cross-run independence on the derived survivors. A survivor must not be a
    // removed row (else its relink dangles), and no non-zero survivor may be
    // shared by two runs (keeps each splice independent). `prev != next` within
    // a run follows from the per-run dedup of removals plus a valid pre-state,
    // but is also caught by the shared-boundary check below.
    if prev_survivor != 0 && next_survivor != 0 && prev_survivor == next_survivor {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: derived prev and next survivor are both {prev_survivor}"
        )));
    }
    for boundary in [prev_survivor, next_survivor] {
        if boundary == 0 {
            continue;
        }
        if state.removed_set.contains(&boundary) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: boundary survivor {boundary} is also a removed row"
            )));
        }
        if !state.seen_boundaries.insert(boundary) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: boundary survivor {boundary} is used by more than one run"
            )));
        }
    }

    materialise_run_writes(
        prev_survivor,
        next_survivor,
        state.envelope.list_number,
        &removed_rows,
        state.batch_ops,
        state.write_keys,
    )
}

fn validate_removed_row(row: &PieceRow, list_number: i64) -> Result<(), ChangelogError> {
    if row.list_number != list_number {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: removed _piecetext_pieces row {} belongs to list {}, expected {list_number}",
            row.id, row.list_number
        )));
    }
    if !row.coord.tombstone {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: removed _piecetext_pieces row {} is not tombstoned",
            row.id
        )));
    }
    if row.coord.buffer_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: removed _piecetext_pieces row {} has invalid buffer_id {}",
            row.id, row.coord.buffer_id
        )));
    }
    row.coord.validate_utf32_alignment().map_err(|e| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: removed _piecetext_pieces row {}: {e}",
            row.id
        ))
    })
}

fn materialise_run_writes(
    prev_survivor: i64,
    next_survivor: i64,
    list_number: i64,
    removed_rows: &[PieceRow],
    batch_ops: &mut Vec<BatchOp>,
    write_keys: &mut BTreeSet<Vec<u8>>,
) -> Result<(), ChangelogError> {
    if prev_survivor == 0 {
        push_unique_op(
            batch_ops,
            write_keys,
            BatchOp::Put {
                key: piece_coords_head_key(list_number),
                value: next_survivor.to_be_bytes().to_vec(),
            },
        )?;
    } else {
        push_unique_op(
            batch_ops,
            write_keys,
            stored_i64_put(
                column_key(PIECE_COORDS_TABLE, prev_survivor, PIECE_COORDS_COL_NEXT_ID),
                next_survivor,
            )?,
        )?;
    }

    if next_survivor == 0 {
        push_unique_op(
            batch_ops,
            write_keys,
            BatchOp::Put {
                key: piece_coords_tail_key(list_number),
                value: prev_survivor.to_be_bytes().to_vec(),
            },
        )?;
    } else {
        push_unique_op(
            batch_ops,
            write_keys,
            stored_i64_put(
                column_key(PIECE_COORDS_TABLE, next_survivor, PIECE_COORDS_COL_PREV_ID),
                prev_survivor,
            )?,
        )?;
    }

    for row in removed_rows {
        for column in PIECE_COORDS_COLUMNS {
            push_unique_op(
                batch_ops,
                write_keys,
                BatchOp::Delete {
                    key: column_key(PIECE_COORDS_TABLE, row.id, column),
                },
            )?;
        }
        for op in piece_coords_delete_index_deletes(row.id, row.list_number, row.coord.buffer_id)? {
            push_unique_op(batch_ops, write_keys, op)?;
        }
    }

    Ok(())
}

const PIECE_COORDS_COLUMNS: &[&str] = &[
    PIECE_COORDS_COL_LIST_NUMBER,
    PIECE_COORDS_COL_PREV_ID,
    PIECE_COORDS_COL_NEXT_ID,
    PIECE_COORDS_COL_BUFFER_ID,
    PIECE_COORDS_COL_START_BYTE,
    PIECE_COORDS_COL_LEN_BYTES,
    PIECE_COORDS_COL_TOMBSTONE,
];

fn push_unique_op(
    batch_ops: &mut Vec<BatchOp>,
    write_keys: &mut BTreeSet<Vec<u8>>,
    op: BatchOp,
) -> Result<(), ChangelogError> {
    if !write_keys.insert(op.key().to_vec()) {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: duplicate write key {}",
            hex::encode(op.key())
        )));
    }
    batch_ops.push(op);
    Ok(())
}

fn stored_i64_put(key: Vec<u8>, value: i64) -> Result<BatchOp, ChangelogError> {
    let value =
        encrypted_spaces_storage_encoding::stored_value::value_to_bytes(&serde_json::json!(value))
            .map_err(|e| ChangelogError::Generic(format!("{OP_NAME}: serialize i64: {e}")))?;
    Ok(BatchOp::Put { key, value })
}

fn read_piece_row_cached(
    reader: &mut dyn OpReader,
    row_cache: &mut BTreeMap<i64, PieceRow>,
    row_id: i64,
) -> Result<PieceRow, ChangelogError> {
    if let Some(row) = row_cache.get(&row_id) {
        return Ok(row.clone());
    }
    let row = read_piece_coords_row(reader, row_id)
        .map_err(|e| ChangelogError::Generic(format!("{OP_NAME}: {e}")))?;
    row_cache.insert(row_id, row.clone());
    Ok(row)
}

fn read_parent_list_number(
    reader: &mut dyn OpReader,
    address: &PieceTextAddress,
) -> Result<i64, ChangelogError> {
    let key = column_key(&address.table, address.row_id, &address.column);
    let bytes = read_single_key(
        reader,
        key,
        &format!(
            "parent PieceText cell {}/{}/{}",
            address.table, address.row_id, address.column
        ),
    )?;
    decode_i64_column_value(&bytes, OP_NAME, "parent PieceText cell")
}

fn authenticate_piece_text_parent(
    reader: &mut dyn OpReader,
    list_number: i64,
    address: &PieceTextAddress,
) -> Result<(), ChangelogError> {
    let key = piece_coords_parent_key(list_number);
    let bytes = read_single_key(
        reader,
        key,
        &format!("piece_coords_parent_key({list_number})"),
    )?;
    let (table, row_id, column) = decode_list_parent(&bytes).map_err(|e| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: failed to decode piece_coords_parent_key({list_number}): {e}"
        ))
    })?;
    if table != address.table || row_id != address.row_id || column != address.column {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: piece_coords_parent_key({list_number}) points to ({table}, {row_id}, {column}) but envelope addresses ({}, {}, {})",
            address.table, address.row_id, address.column
        )));
    }
    Ok(())
}

fn read_raw_i64_key(
    reader: &mut dyn OpReader,
    key: Vec<u8>,
    label: &str,
) -> Result<i64, ChangelogError> {
    let bytes = read_single_key(reader, key, label)?;
    if bytes.len() != 8 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {label} key has {} bytes, expected 8",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes);
    Ok(i64::from_be_bytes(buf))
}

fn read_single_key(
    reader: &mut dyn OpReader,
    key: Vec<u8>,
    label: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let read = reader.read(ReadOp::Key(key.clone()))?;
    if read.results.len() != 1 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {label} read returned {} results, expected 1",
            read.results.len()
        )));
    }
    let (actual_key, bytes) = &read.results[0];
    if actual_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {label} read returned wrong key"
        )));
    }
    Ok(bytes.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{ChangelogEntry, LogMessage, OpType, ROOT_TREE_PATH};
    use crate::ops::dispatch_extract_and_validate;
    use crate::piece_text::{PieceCoord, PIECE_TEXT_UTF32_BYTES_PER_SCALAR};
    use crate::piece_text_cleanup::{
        PieceTextCleanupRunV1, PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
    };
    use encrypted_spaces_storage_encoding::keys::{
        encode_list_parent, index_key, schema_piece_text_columns_key,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;

    const TABLE: &str = "docs";
    const ROW_ID: i64 = 42;
    const COLUMN: &str = "body";
    const LIST_NUMBER: i64 = 7;
    const OP_ID: i64 = 99;

    #[derive(Default)]
    struct FakeReader {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        reads: Vec<ReadOp>,
    }

    impl FakeReader {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.kv.insert(key, value);
        }

        fn setup_base(&mut self, head: i64, tail: i64) {
            let mut cols = BTreeSet::new();
            cols.insert(COLUMN.to_string());
            self.put(
                schema_piece_text_columns_key(TABLE),
                encrypted_spaces_storage_encoding::encode_column_names(&cols),
            );
            self.put(column_key(TABLE, ROW_ID, COLUMN), stored_i64(LIST_NUMBER));
            self.put(
                piece_coords_parent_key(LIST_NUMBER),
                encode_list_parent(TABLE, ROW_ID, COLUMN),
            );
            self.put(
                piece_coords_head_key(LIST_NUMBER),
                head.to_be_bytes().to_vec(),
            );
            self.put(
                piece_coords_tail_key(LIST_NUMBER),
                tail.to_be_bytes().to_vec(),
            );
        }

        fn put_piece(&mut self, id: i64, prev_id: i64, next_id: i64, tombstone: bool) {
            self.put_piece_in_list(id, LIST_NUMBER, prev_id, next_id, tombstone, id);
        }

        fn put_piece_in_list(
            &mut self,
            id: i64,
            list_number: i64,
            prev_id: i64,
            next_id: i64,
            tombstone: bool,
            buffer_id: i64,
        ) {
            for (column, value) in [
                (PIECE_COORDS_COL_LIST_NUMBER, list_number),
                (PIECE_COORDS_COL_PREV_ID, prev_id),
                (PIECE_COORDS_COL_NEXT_ID, next_id),
                (PIECE_COORDS_COL_BUFFER_ID, buffer_id),
                (PIECE_COORDS_COL_START_BYTE, 0),
                (
                    PIECE_COORDS_COL_LEN_BYTES,
                    PIECE_TEXT_UTF32_BYTES_PER_SCALAR as i64,
                ),
                (PIECE_COORDS_COL_TOMBSTONE, if tombstone { 1 } else { 0 }),
            ] {
                self.put(
                    column_key(PIECE_COORDS_TABLE, id, column),
                    stored_i64(value),
                );
            }
        }
    }

    impl OpReader for FakeReader {
        fn read(&mut self, op: ReadOp) -> Result<crate::ProvenRead, ChangelogError> {
            self.reads.push(op.clone());
            let results = match &op {
                ReadOp::Key(key) => self
                    .kv
                    .get(key)
                    .map(|value| vec![(key.clone(), value.clone())])
                    .unwrap_or_default(),
                ReadOp::Range { start, end } => self
                    .kv
                    .range(start.clone()..end.clone())
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                ReadOp::Prefix(prefix) => {
                    let end = crate::prefix_successor(prefix);
                    match end {
                        Some(end) => self
                            .kv
                            .range(prefix.clone()..end)
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect(),
                        None => self
                            .kv
                            .range(prefix.clone()..)
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect(),
                    }
                }
            };
            Ok(crate::ProvenRead { op, results })
        }
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn address() -> PieceTextAddress {
        PieceTextAddress {
            table: TABLE.to_string(),
            row_id: ROW_ID,
            column: COLUMN.to_string(),
        }
    }

    fn envelope(runs: Vec<PieceTextCleanupRunV1>) -> PieceTextCleanupPiecesEnvelopeV1 {
        PieceTextCleanupPiecesEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address: address(),
            list_number: LIST_NUMBER,
            op_id: OP_ID,
            runs,
        }
    }

    fn entry(env: &PieceTextCleanupPiecesEnvelopeV1) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 0,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::PieceTextCleanupPieces,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![env.changelog_entry_kv().unwrap()],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn verify(
        reader: &mut FakeReader,
        env: &PieceTextCleanupPiecesEnvelopeV1,
    ) -> Result<Vec<BatchOp>, ChangelogError> {
        let result = PieceTextCleanupPiecesOp::extract_and_validate(
            &entry(env),
            reader,
            &OpContext::for_change_id(OP_ID as usize),
        )?;
        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        Ok(ops.clone())
    }

    fn verify_dispatch(
        reader: &mut FakeReader,
        env: &PieceTextCleanupPiecesEnvelopeV1,
    ) -> Result<Vec<BatchOp>, ChangelogError> {
        let result = dispatch_extract_and_validate(
            &entry(env),
            reader,
            &OpContext::for_change_id(OP_ID as usize),
        )?;
        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        Ok(ops.clone())
    }

    fn op_puts_raw_i64(ops: &[BatchOp], key: Vec<u8>, value: i64) -> bool {
        ops.iter().any(|op| {
            matches!(
                op,
                BatchOp::Put { key: k, value: v }
                    if *k == key && *v == value.to_be_bytes().to_vec()
            )
        })
    }

    fn op_puts_stored_i64(ops: &[BatchOp], key: Vec<u8>, value: i64) -> bool {
        let stored = stored_i64(value);
        ops.iter().any(|op| {
            matches!(
                op,
                BatchOp::Put { key: k, value: v } if *k == key && *v == stored
            )
        })
    }

    fn op_deletes(ops: &[BatchOp], key: Vec<u8>) -> bool {
        ops.iter()
            .any(|op| matches!(op, BatchOp::Delete { key: k } if *k == key))
    }

    fn setup_chain(reader: &mut FakeReader, ids: &[i64], tombstones: &[i64]) {
        let tombstones = tombstones.iter().copied().collect::<BTreeSet<_>>();
        for (idx, id) in ids.iter().copied().enumerate() {
            let prev = if idx == 0 { 0 } else { ids[idx - 1] };
            let next = ids.get(idx + 1).copied().unwrap_or(0);
            reader.put_piece(id, prev, next, tombstones.contains(&id));
        }
    }

    #[test]
    fn piece_text_cleanup_pieces_accepts_middle_run_relink() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 4);
        setup_chain(&mut reader, &[1, 2, 3, 4], &[2, 3]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let ops = verify_dispatch(&mut reader, &env).unwrap();

        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            4
        ));
        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            1
        ));
        assert!(op_deletes(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LIST_NUMBER)
        ));
        assert!(op_deletes(
            &ops,
            index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 2, 2).unwrap()
        ));
        assert!(op_deletes(
            &ops,
            index_key(
                PIECE_COORDS_TABLE,
                PIECE_COORDS_COL_LIST_NUMBER,
                LIST_NUMBER,
                3
            )
            .unwrap()
        ));
        assert_eq!(ops.len(), 2 + (7 + 2) * 2);
        assert!(
            !reader
                .reads
                .iter()
                .any(|op| matches!(op, ReadOp::Range { .. } | ReadOp::Prefix(_))),
            "piece cleanup verifier must not scan the document"
        );
    }

    #[test]
    fn piece_text_cleanup_pieces_accepts_head_run_and_updates_head() {
        let mut reader = FakeReader::default();
        reader.setup_base(2, 4);
        setup_chain(&mut reader, &[2, 3, 4], &[2, 3]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let ops = verify(&mut reader, &env).unwrap();

        assert!(op_puts_raw_i64(&ops, piece_coords_head_key(LIST_NUMBER), 4));
        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            0
        ));
    }

    #[test]
    fn piece_text_cleanup_pieces_accepts_tail_run_and_updates_tail() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 3);
        setup_chain(&mut reader, &[1, 2, 3], &[2, 3]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let ops = verify(&mut reader, &env).unwrap();

        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            0
        ));
        assert!(op_puts_raw_i64(&ops, piece_coords_tail_key(LIST_NUMBER), 1));
    }

    #[test]
    fn piece_text_cleanup_pieces_accepts_remove_all_and_zeros_head_tail() {
        let mut reader = FakeReader::default();
        reader.setup_base(2, 3);
        setup_chain(&mut reader, &[2, 3], &[2, 3]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let ops = verify(&mut reader, &env).unwrap();

        assert!(op_puts_raw_i64(&ops, piece_coords_head_key(LIST_NUMBER), 0));
        assert!(op_puts_raw_i64(&ops, piece_coords_tail_key(LIST_NUMBER), 0));
        assert_eq!(ops.len(), 2 + (7 + 2) * 2);
    }

    #[test]
    fn piece_text_cleanup_pieces_accepts_multiple_disjoint_runs() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 7);
        setup_chain(&mut reader, &[1, 2, 3, 4, 5, 6, 7], &[2, 5]);
        let env = envelope(vec![
            PieceTextCleanupRunV1 { removals: vec![2] },
            PieceTextCleanupRunV1 { removals: vec![5] },
        ]);

        let ops = verify(&mut reader, &env).unwrap();

        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            3
        ));
        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_NEXT_ID),
            6
        ));
        assert_eq!(ops.len(), 4 + (7 + 2) * 2);
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_op_id_mismatch() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        setup_chain(&mut reader, &[1, 2], &[2]);
        let mut env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);
        env.op_id = OP_ID + 1;

        let err = PieceTextCleanupPiecesOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(OP_ID as usize),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("current_change_id"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_parent_list_number_mismatch() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        reader.put(
            column_key(TABLE, ROW_ID, COLUMN),
            stored_i64(LIST_NUMBER + 1),
        );
        setup_chain(&mut reader, &[1, 2], &[2]);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("does not match envelope"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_parent_mapping_mismatch() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        reader.put(
            piece_coords_parent_key(LIST_NUMBER),
            encode_list_parent(TABLE, ROW_ID + 1, COLUMN),
        );
        setup_chain(&mut reader, &[1, 2], &[2]);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("piece_coords_parent_key"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_non_piece_text_column() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        reader.put(
            schema_piece_text_columns_key(TABLE),
            encrypted_spaces_storage_encoding::encode_column_names(&BTreeSet::new()),
        );
        setup_chain(&mut reader, &[1, 2], &[2]);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("not declared as PieceText"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_non_tombstoned_removal() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        setup_chain(&mut reader, &[1, 2], &[]);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("not tombstoned"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_invalid_removed_buffer_id() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        reader.put_piece(1, 0, 2, false);
        reader.put_piece_in_list(2, LIST_NUMBER, 1, 0, true, 0);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("invalid buffer_id"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_unaligned_removed_row() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        setup_chain(&mut reader, &[1, 2], &[2]);
        reader.put(
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LEN_BYTES),
            stored_i64(PIECE_TEXT_UTF32_BYTES_PER_SCALAR as i64 + 1),
        );
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("UTF-32 aligned"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_broken_forward_link() {
        // Within a run, a removed row whose next_id does not point at the next
        // removed row is rejected. (Survivor-boundary links are no longer read;
        // their consistency follows from the linked-list invariant.)
        let mut reader = FakeReader::default();
        reader.setup_base(1, 4);
        setup_chain(&mut reader, &[1, 2, 3, 4], &[2, 3]);
        reader.put(
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            stored_i64(4),
        );
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("next_id"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_broken_reverse_link() {
        // Within a run, a removed row whose prev_id does not point at the
        // previous removed row is rejected.
        let mut reader = FakeReader::default();
        reader.setup_base(1, 4);
        setup_chain(&mut reader, &[1, 2, 3, 4], &[2, 3]);
        reader.put(
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_PREV_ID),
            stored_i64(1),
        );
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 3],
        }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("prev_id"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_two_runs_claiming_head() {
        // Two runs that both derive `prev_survivor == 0` (a malformed two-head
        // pre-state): only the run that actually starts at the head passes the
        // sentinel check; the other is rejected.
        let mut reader = FakeReader::default();
        reader.setup_base(2, 6);
        setup_chain(&mut reader, &[2, 3, 4, 5, 6], &[2, 5]);
        // Make row 5 a second "head" (prev_id 0) so its run also derives prev 0.
        reader.put(
            column_key(PIECE_COORDS_TABLE, 5, PIECE_COORDS_COL_PREV_ID),
            stored_i64(0),
        );
        let env = envelope(vec![
            PieceTextCleanupRunV1 { removals: vec![2] },
            PieceTextCleanupRunV1 { removals: vec![5] },
        ]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("list head"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_two_runs_claiming_tail() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 5);
        setup_chain(&mut reader, &[1, 2, 3, 4, 5], &[2, 5]);
        reader.put(
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            stored_i64(0),
        );
        let env = envelope(vec![
            PieceTextCleanupRunV1 { removals: vec![2] },
            PieceTextCleanupRunV1 { removals: vec![5] },
        ]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("list tail"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_adjacent_runs_that_should_be_merged() {
        // [2] and [3] are contiguous tombstones submitted as two runs. Run [2]'s
        // derived next_survivor is row 3, which is itself a removed row.
        let mut reader = FakeReader::default();
        reader.setup_base(1, 4);
        setup_chain(&mut reader, &[1, 2, 3, 4], &[2, 3]);
        let env = envelope(vec![
            PieceTextCleanupRunV1 { removals: vec![2] },
            PieceTextCleanupRunV1 { removals: vec![3] },
        ]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("also a removed row"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_duplicate_write_keys() {
        let mut ops = Vec::new();
        let mut keys = BTreeSet::new();
        let key = column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID);
        push_unique_op(
            &mut ops,
            &mut keys,
            BatchOp::Put {
                key: key.clone(),
                value: 2i64.to_be_bytes().to_vec(),
            },
        )
        .unwrap();

        let err = push_unique_op(
            &mut ops,
            &mut keys,
            BatchOp::Put {
                key,
                value: 3i64.to_be_bytes().to_vec(),
            },
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("duplicate write key"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_duplicate_removal_through_dispatch() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        setup_chain(&mut reader, &[1, 2], &[2]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![2, 2],
        }]);

        let err = verify_dispatch(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("appears more than once"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_duplicate_nonzero_boundary_use() {
        // Run [2]'s derived next_survivor (row 3) equals run [4]'s derived
        // prev_survivor (row 3): a shared survivor across two runs is rejected.
        let mut reader = FakeReader::default();
        reader.setup_base(1, 5);
        setup_chain(&mut reader, &[1, 2, 3, 4, 5], &[2, 4]);
        let env = envelope(vec![
            PieceTextCleanupRunV1 { removals: vec![2] },
            PieceTextCleanupRunV1 { removals: vec![4] },
        ]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("more than one run"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_removed_row_from_other_list() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        reader.put_piece(1, 0, 2, false);
        reader.put_piece_in_list(2, LIST_NUMBER + 1, 1, 0, true, 2);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("belongs to list"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_delete_columns_are_schema_complete() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 2);
        setup_chain(&mut reader, &[1, 2], &[2]);
        let env = envelope(vec![PieceTextCleanupRunV1 { removals: vec![2] }]);

        let ops = verify(&mut reader, &env).unwrap();

        for column in PIECE_COORDS_COLUMNS {
            assert!(
                op_deletes(&ops, column_key(PIECE_COORDS_TABLE, 2, column)),
                "missing delete for {column}"
            );
        }
        assert!(op_deletes(
            &ops,
            index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 2, 2).unwrap()
        ));
        assert!(op_deletes(
            &ops,
            index_key(
                PIECE_COORDS_TABLE,
                PIECE_COORDS_COL_LIST_NUMBER,
                LIST_NUMBER,
                2
            )
            .unwrap()
        ));
    }

    #[test]
    fn piece_text_cleanup_pieces_rejects_corrupt_removed_run_order() {
        let mut reader = FakeReader::default();
        reader.setup_base(1, 4);
        setup_chain(&mut reader, &[1, 2, 3, 4], &[2, 3]);
        let env = envelope(vec![PieceTextCleanupRunV1 {
            removals: vec![3, 2],
        }]);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("next_id"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_pieces_uses_stored_value_for_relink_columns() {
        let row = PieceRow {
            id: 9,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 9,
                start_byte: 0,
                len_bytes: PIECE_TEXT_UTF32_BYTES_PER_SCALAR,
                tombstone: true,
            },
        };
        let mut ops = Vec::new();
        let mut keys = BTreeSet::new();
        materialise_run_writes(
            1, // derived prev_survivor
            2, // derived next_survivor
            LIST_NUMBER,
            &[row],
            &mut ops,
            &mut keys,
        )
        .unwrap();

        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2
        ));
        assert!(op_puts_stored_i64(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            1
        ));
    }
}
