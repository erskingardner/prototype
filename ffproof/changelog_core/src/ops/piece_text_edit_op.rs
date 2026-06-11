use std::collections::{BTreeMap, BTreeSet};

use super::{
    decode_i64_column_value, enforce_only_via_actions, evaluate_acl, next_id_put, read_acl_rule,
    read_columns_from_tree, read_next_id, read_schema_piece_text_columns, validate_user_access,
    OpContext, OpReader, OpVerifier, OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError, OpType};
use crate::piece_text::{
    PieceCoord, PieceTextAddress, PieceTextEditEnvelopeV1, PieceTextEditItemManifest,
    MAX_BUFFER_LEN_BYTES,
};
use crate::piece_text_overlay::IndexedPieceEditPlanner;
use crate::piece_text_planner::{BufferMeta, PieceRow, PlannerOutput};
use crate::piece_text_resolver::{
    buffers_insert_index_puts, piece_coords_insert_index_puts, BUFFERS_COL_OWNER_COLUMN,
    BUFFERS_COL_OWNER_ROW_ID, BUFFERS_COL_OWNER_TABLE, PIECE_COORDS_COL_BUFFER_ID,
    PIECE_COORDS_COL_LEN_BYTES, PIECE_COORDS_COL_LIST_NUMBER, PIECE_COORDS_COL_NEXT_ID,
    PIECE_COORDS_COL_PREV_ID, PIECE_COORDS_COL_START_BYTE, PIECE_COORDS_COL_TOMBSTONE,
};
use crate::{BatchOp, ReadOp, TraceStep};
use encrypted_spaces_storage_encoding::keys::{
    column_key, decode_list_parent, piece_coords_head_key, piece_coords_parent_key,
    piece_coords_tail_key, BUFFERS_TABLE, PIECE_COORDS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::{bytes_to_value, value_to_bytes};

pub struct PieceTextEditOp;

const OP_NAME: &str = "piece_text_edit";

/// Observability counters for one verified `PieceTextEdit`.
///
/// `piece_rows_read` counts distinct pre-existing `_piecetext_pieces` rows
/// authenticated by indexed edit planning. It is a touched-row count, not a
/// document-wide live/tombstone count.
///
/// The verifier runs inside the zkVM guest and cannot log; native callers
/// obtain these via [`PieceTextEditOp::extract_and_validate_with_metrics`] and
/// are responsible for emitting them to logs/metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PieceTextEditExecutionMetrics {
    /// Distinct pre-existing `_piecetext_pieces` rows authenticated while planning.
    pub piece_rows_read: usize,
    /// Distinct existing `_piecetext_buffers` rows validated for touched pieces.
    pub buffer_rows_read: usize,
    pub inserted_piece_rows: usize,
    pub updated_piece_rows: usize,
    pub inserted_buffer_rows: usize,
    pub write_ops: usize,
}

impl OpVerifier for PieceTextEditOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let (result, _) = Self::extract_and_validate_with_metrics(entry, reader, ctx)?;
        Ok(result)
    }
}

impl PieceTextEditOp {
    pub fn extract_and_validate_with_metrics(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<(OpVerifyResult, PieceTextEditExecutionMetrics), ChangelogError> {
        let envelope = PieceTextEditEnvelopeV1::decode_from_entry(entry)?;

        validate_user_access(entry, OpType::PieceTextEdit, OP_NAME, reader)?;
        enforce_only_via_actions(&envelope.address.table, "write", OP_NAME, ctx, reader)?;

        let piece_text_columns =
            read_schema_piece_text_columns(&envelope.address.table, reader, ctx)?;
        if !piece_text_columns.contains(&envelope.address.column) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: column '{}.{}' is not declared as PieceText",
                envelope.address.table, envelope.address.column
            )));
        }

        let list_number = read_parent_list_number(reader, &envelope.address)?;
        if list_number <= 0 {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: parent PieceText cell has invalid list_number {list_number}"
            )));
        }
        authenticate_piece_text_parent(reader, list_number, &envelope.address)?;

        enforce_parent_write_acl(entry.uid, &envelope.address, reader, ctx)?;

        let has_inserts = envelope
            .edit
            .ops
            .iter()
            .any(|op| matches!(op, PieceTextEditItemManifest::Insert { .. }));

        let head_id = read_raw_i64_key(reader, piece_coords_head_key(list_number), "head")?;
        let tail_id = read_raw_i64_key(reader, piece_coords_tail_key(list_number), "tail")?;
        let pre_piece_next_id = read_next_id(PIECE_COORDS_TABLE, OP_NAME, reader)?;
        let pre_buffers_next_id = if has_inserts {
            read_next_id(BUFFERS_TABLE, OP_NAME, reader)?
        } else {
            1
        };

        let mut planner = IndexedPieceEditPlanner::new(
            reader,
            envelope.address.clone(),
            list_number,
            entry.uid as i64,
            head_id,
            tail_id,
            pre_piece_next_id,
            pre_buffers_next_id,
        )
        .map_err(indexed_planner_error)?;
        planner
            .apply_ops(&envelope.edit.ops)
            .map_err(indexed_planner_error)?;
        let output = planner.into_output();
        let authenticated_piece_coords = output.trace.authenticated_piece_coords.clone();
        let piece_rows_read = authenticated_piece_coords.len();
        let original_coords = authenticated_piece_coords
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        let buffer_rows_read = validate_authenticated_piece_buffers(
            reader,
            &envelope.address,
            &authenticated_piece_coords,
        )?;

        let batch_ops =
            materialise_planner_output(&envelope, list_number, &output, &original_coords)?;
        let metrics = PieceTextEditExecutionMetrics {
            piece_rows_read,
            buffer_rows_read,
            inserted_piece_rows: output.piece_inserts.len(),
            updated_piece_rows: output.piece_updates.len(),
            inserted_buffer_rows: output.buffer_inserts.len(),
            write_ops: batch_ops.len(),
        };

        Ok((
            OpVerifyResult {
                write_steps: vec![TraceStep::Write(batch_ops)],
            },
            metrics,
        ))
    }
}

fn indexed_planner_error(err: ChangelogError) -> ChangelogError {
    ChangelogError::Generic(format!("{OP_NAME}: {err}"))
}

fn validate_authenticated_piece_buffers(
    reader: &mut dyn OpReader,
    address: &PieceTextAddress,
    authenticated_piece_coords: &[(i64, PieceCoord)],
) -> Result<usize, ChangelogError> {
    let buffer_ids = authenticated_piece_coords
        .iter()
        .map(|(_, coord)| coord.buffer_id)
        .collect::<BTreeSet<_>>();
    let mut buffers = BTreeMap::new();
    for buffer_id in &buffer_ids {
        let meta = read_buffer_meta(reader, *buffer_id)?;
        if meta.owner_table != address.table
            || meta.owner_row_id != address.row_id
            || meta.owner_column != address.column
        {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: buffer {buffer_id} owner address ({}, {}, {}) does not match envelope ({}, {}, {})",
                meta.owner_table,
                meta.owner_row_id,
                meta.owner_column,
                address.table,
                address.row_id,
                address.column
            )));
        }
        buffers.insert(*buffer_id, meta);
    }
    for (row_id, coord) in authenticated_piece_coords {
        let Some(meta) = buffers.get(&coord.buffer_id) else {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: _piecetext_pieces row {row_id} references missing buffer {}",
                coord.buffer_id
            )));
        };
        let end = coord
            .start_byte
            .checked_add(coord.len_bytes)
            .ok_or_else(|| {
                ChangelogError::Generic(format!(
                    "{OP_NAME}: _piecetext_pieces row {row_id} range overflows"
                ))
            })?;
        if end > meta.len_bytes {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: _piecetext_pieces row {row_id} range exceeds buffer {} len_bytes ({} > {})",
                meta.id, end, meta.len_bytes
            )));
        }
    }
    Ok(buffer_ids.len())
}

fn enforce_parent_write_acl(
    uid: u32,
    address: &PieceTextAddress,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<(), ChangelogError> {
    let Some(rule) = read_acl_rule(reader, &address.table, "write", ctx)? else {
        return Ok(());
    };
    let mut needed_columns = Vec::new();
    rule.collect_resource_columns(&mut needed_columns);
    let acl = super::AclCheck {
        rule,
        resource_name: address.table.clone(),
        needed_columns,
    };
    let values =
        read_columns_from_tree(&address.table, address.row_id, &acl.needed_columns, reader)?;
    evaluate_acl(&acl, uid, &values, OP_NAME)
}

fn read_parent_list_number(
    reader: &mut dyn OpReader,
    address: &PieceTextAddress,
) -> Result<i64, ChangelogError> {
    let key = column_key(&address.table, address.row_id, &address.column);
    let read = reader.read(ReadOp::Key(key.clone()))?;
    let (returned_key, bytes) = read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: parent PieceText cell {}/{}/{} is absent",
            address.table, address.row_id, address.column
        ))
    })?;
    if returned_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: parent PieceText cell read returned wrong key"
        )));
    }
    decode_i64_column_value(bytes, OP_NAME, "parent PieceText cell")
}

fn authenticate_piece_text_parent(
    reader: &mut dyn OpReader,
    list_number: i64,
    address: &PieceTextAddress,
) -> Result<(), ChangelogError> {
    let key = piece_coords_parent_key(list_number);
    let read = reader.read(ReadOp::Key(key.clone()))?;
    let (returned_key, bytes) = read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: piece_coords_parent_key({list_number}) is missing"
        ))
    })?;
    if returned_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: piece_coords_parent_key({list_number}) read returned wrong key"
        )));
    }
    let (table, row_id, column) = decode_list_parent(bytes).map_err(|e| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: failed to decode piece_coords_parent_key({list_number}): {e}"
        ))
    })?;
    if table != address.table || row_id != address.row_id || column != address.column {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: piece_coords_parent_key({list_number}) points to ({table}, {row_id}, {column}) \
             but envelope addresses ({}, {}, {})",
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
    let read = reader.read(ReadOp::Key(key.clone()))?;
    let (returned_key, bytes) = read
        .results
        .first()
        .ok_or_else(|| ChangelogError::Generic(format!("{OP_NAME}: {label} key is missing")))?;
    if returned_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {label} key read returned wrong key"
        )));
    }
    if bytes.len() != 8 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {label} key has {} bytes, expected 8",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(i64::from_be_bytes(buf))
}

fn read_buffer_meta(
    reader: &mut dyn OpReader,
    buffer_id: i64,
) -> Result<BufferMeta, ChangelogError> {
    if buffer_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: buffer_id must be positive, got {buffer_id}"
        )));
    }
    let owner_table =
        read_string_column(reader, BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_TABLE)?;
    let owner_row_id = read_i64_column(reader, BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_ROW_ID)?;
    let owner_column =
        read_string_column(reader, BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_COLUMN)?;
    let author_id = read_i64_column(reader, BUFFERS_TABLE, buffer_id, "author_id")?;
    let len_i64 = read_i64_column(reader, BUFFERS_TABLE, buffer_id, "len_bytes")?;
    let len_bytes = u32::try_from(len_i64).map_err(|_| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: _piecetext_buffers row {buffer_id}.len_bytes {len_i64} is outside u32 range"
        ))
    })?;
    if len_bytes == 0 || len_bytes > MAX_BUFFER_LEN_BYTES {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: _piecetext_buffers row {buffer_id}.len_bytes {len_bytes} is outside 1..={MAX_BUFFER_LEN_BYTES}"
        )));
    }
    Ok(BufferMeta {
        id: buffer_id,
        owner_table,
        owner_row_id,
        owner_column,
        author_id,
        len_bytes,
    })
}

fn read_string_column(
    reader: &mut dyn OpReader,
    table: &str,
    row_id: i64,
    column: &str,
) -> Result<String, ChangelogError> {
    let bytes = read_column_bytes(reader, table, row_id, column)?;
    bytes_to_value(&bytes)
        .map_err(|e| {
            ChangelogError::Generic(format!(
                "{OP_NAME}: failed to decode {table}.{column} row {row_id}: {e}"
            ))
        })?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{OP_NAME}: {table}.{column} row {row_id} is not a string"
            ))
        })
}

fn read_i64_column(
    reader: &mut dyn OpReader,
    table: &str,
    row_id: i64,
    column: &str,
) -> Result<i64, ChangelogError> {
    let bytes = read_column_bytes(reader, table, row_id, column)?;
    decode_i64_column_value(&bytes, OP_NAME, &format!("{table}.{column} row {row_id}"))
}

fn read_column_bytes(
    reader: &mut dyn OpReader,
    table: &str,
    row_id: i64,
    column: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let key = column_key(table, row_id, column);
    let read = reader.read(ReadOp::Key(key.clone()))?;
    let (returned_key, bytes) = read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: {table} row {row_id} column '{column}' is absent"
        ))
    })?;
    if returned_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {table} row {row_id} column '{column}' read returned wrong key"
        )));
    }
    Ok(bytes.clone())
}

fn materialise_planner_output(
    envelope: &PieceTextEditEnvelopeV1,
    list_number: i64,
    output: &PlannerOutput,
    original_coords: &BTreeMap<i64, PieceCoord>,
) -> Result<Vec<BatchOp>, ChangelogError> {
    let mut ops = Vec::new();

    // Derived rows (defense-in-depth): re-check every coord the planner
    // produces before writing it. With aligned envelope inputs the splice
    // math preserves alignment (see the inductive invariant in
    // piece_text_planner.rs), so this only fires on a planner bug — but the
    // verifier must not write a misaligned coord even then.
    for insert in &output.piece_inserts {
        insert.coord.validate_utf32_alignment().map_err(|e| {
            ChangelogError::Generic(format!(
                "{OP_NAME}: planned piece row {}: {e}",
                insert.new_id
            ))
        })?;
    }
    for update in &output.piece_updates {
        if let Some(coord) = update.coord {
            coord.validate_utf32_alignment().map_err(|e| {
                ChangelogError::Generic(format!(
                    "{OP_NAME}: planned update to piece row {}: {e}",
                    update.id
                ))
            })?;
        }
    }

    for insert in &output.buffer_inserts {
        ops.extend(buffer_insert_writes(insert, &envelope.address)?);
    }
    if let Some(next) = output.buffers_next_id_post {
        ops.push(next_id_put(BUFFERS_TABLE, next));
    }

    for insert in &output.piece_inserts {
        let row = PieceRow {
            id: insert.new_id,
            list_number: insert.list_number,
            prev_id: insert.prev_id,
            next_id: insert.next_id,
            coord: insert.coord,
        };
        piece_coords_insert_writes(&mut ops, &row)?;
    }

    for update in &output.piece_updates {
        if let Some(prev_id) = update.prev_id {
            ops.push(stored_i64_put(
                column_key(PIECE_COORDS_TABLE, update.id, PIECE_COORDS_COL_PREV_ID),
                prev_id,
            )?);
        }
        if let Some(next_id) = update.next_id {
            ops.push(stored_i64_put(
                column_key(PIECE_COORDS_TABLE, update.id, PIECE_COORDS_COL_NEXT_ID),
                next_id,
            )?);
        }
        if let Some(coord) = update.coord {
            let Some(original) = original_coords.get(&update.id) else {
                return Err(ChangelogError::Generic(format!(
                    "{OP_NAME}: update references unknown pre-existing piece row {}",
                    update.id
                )));
            };
            if original.buffer_id != coord.buffer_id || original.start_byte != coord.start_byte {
                return Err(ChangelogError::Generic(format!(
                    "{OP_NAME}: piece row {} buffer_id/start_byte changed",
                    update.id
                )));
            }
            ops.push(stored_i64_put(
                column_key(PIECE_COORDS_TABLE, update.id, PIECE_COORDS_COL_LEN_BYTES),
                coord.len_bytes as i64,
            )?);
            ops.push(stored_i64_put(
                column_key(PIECE_COORDS_TABLE, update.id, PIECE_COORDS_COL_TOMBSTONE),
                if coord.tombstone { 1 } else { 0 },
            )?);
        }
    }

    if let Some(next) = output.piece_next_id_post {
        ops.push(next_id_put(PIECE_COORDS_TABLE, next));
    }
    if let Some(head) = output.head_update {
        ops.push(BatchOp::Put {
            key: piece_coords_head_key(list_number),
            value: head.to_be_bytes().to_vec(),
        });
    }
    if let Some(tail) = output.tail_update {
        ops.push(BatchOp::Put {
            key: piece_coords_tail_key(list_number),
            value: tail.to_be_bytes().to_vec(),
        });
    }

    ensure_no_duplicate_write_keys(&ops)?;
    Ok(ops)
}

fn buffer_insert_writes(
    insert: &crate::piece_text_planner::BufferRowInsert,
    address: &PieceTextAddress,
) -> Result<Vec<BatchOp>, ChangelogError> {
    let id = insert.new_id;
    let mut ops = vec![
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, BUFFERS_COL_OWNER_TABLE),
            value: value_to_bytes(&serde_json::Value::String(address.table.clone())).map_err(
                |e| ChangelogError::Generic(format!("{OP_NAME}: serialize owner_table: {e}")),
            )?,
        },
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, BUFFERS_COL_OWNER_ROW_ID),
            value: value_to_bytes(&serde_json::json!(address.row_id)).map_err(|e| {
                ChangelogError::Generic(format!("{OP_NAME}: serialize owner_row_id: {e}"))
            })?,
        },
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, BUFFERS_COL_OWNER_COLUMN),
            value: value_to_bytes(&serde_json::Value::String(address.column.clone())).map_err(
                |e| ChangelogError::Generic(format!("{OP_NAME}: serialize owner_column: {e}")),
            )?,
        },
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, "author_id"),
            value: value_to_bytes(&serde_json::json!(insert.author_id)).map_err(|e| {
                ChangelogError::Generic(format!("{OP_NAME}: serialize author_id: {e}"))
            })?,
        },
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, "len_bytes"),
            value: value_to_bytes(&serde_json::json!(insert.len_bytes as i64)).map_err(|e| {
                ChangelogError::Generic(format!("{OP_NAME}: serialize len_bytes: {e}"))
            })?,
        },
        BatchOp::Put {
            key: column_key(BUFFERS_TABLE, id, "contents"),
            value: insert.ciphertext_value_hash.to_vec(),
        },
    ];
    ops.extend(buffers_insert_index_puts(
        id,
        &address.table,
        address.row_id,
        &address.column,
    )?);
    Ok(ops)
}

fn piece_coords_insert_writes(
    ops: &mut Vec<BatchOp>,
    row: &PieceRow,
) -> Result<(), ChangelogError> {
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_LIST_NUMBER),
        row.list_number,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_PREV_ID),
        row.prev_id,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_NEXT_ID),
        row.next_id,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_BUFFER_ID),
        row.coord.buffer_id,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_START_BYTE),
        row.coord.start_byte as i64,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_LEN_BYTES),
        row.coord.len_bytes as i64,
    )?);
    ops.push(stored_i64_put(
        column_key(PIECE_COORDS_TABLE, row.id, PIECE_COORDS_COL_TOMBSTONE),
        if row.coord.tombstone { 1 } else { 0 },
    )?);
    ops.extend(piece_coords_insert_index_puts(
        row.id,
        row.list_number,
        row.coord.buffer_id,
    )?);
    Ok(())
}

fn stored_i64_put(key: Vec<u8>, value: i64) -> Result<BatchOp, ChangelogError> {
    let value = value_to_bytes(&serde_json::json!(value))
        .map_err(|e| ChangelogError::Generic(format!("{OP_NAME}: serialize i64: {e}")))?;
    Ok(BatchOp::Put { key, value })
}

fn ensure_no_duplicate_write_keys(ops: &[BatchOp]) -> Result<(), ChangelogError> {
    let mut seen = BTreeSet::new();
    for op in ops {
        if !seen.insert(op.key().to_vec()) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: duplicate write key {}",
                hex::encode(op.key())
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{ChangelogEntry, LogMessage, ROOT_TREE_PATH};
    use crate::piece_text::{
        BufferCoord, InsertedBufferManifest, PieceTextEditManifest, PIECE_TEXT_ENVELOPE_VERSION_V1,
    };
    use encrypted_spaces_storage_encoding::keys::{
        encode_list_parent, index_column_prefix, index_key, piece_coords_head_key,
        piece_coords_tail_key, row_id_to_bytes, schema_next_id_key, schema_piece_text_columns_key,
        USERS_TABLE,
    };
    use ffproof_tracer_shared::prefix_successor;

    const UID: u32 = 7;
    const TABLE: &str = "docs";
    const ROW_ID: i64 = 42;
    const COLUMN: &str = "body";
    const LIST_NUMBER: i64 = 5;

    #[derive(Default)]
    struct FakeReader {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        /// Every `ReadOp` issued against this reader, in order. The Stage 0
        /// guard test inspects this to prove `PieceTextEditOp` never range-reads
        /// the whole `_piecetext_pieces.list_number` index for a document.
        reads: Vec<ReadOp>,
    }

    impl FakeReader {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.kv.insert(key, value);
        }

        /// Seed one `_piecetext_pieces` row: its seven stored columns plus the
        /// `list_number` and `buffer_id` secondary index entries.
        fn put_piece_row(&mut self, row: &PieceRow) {
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
                    PIECE_COORDS_COL_LIST_NUMBER,
                    row.list_number,
                    row.id,
                )
                .unwrap(),
                row_id_to_bytes(row.id).to_vec(),
            );
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

        /// Seed the owner/metadata columns of one `_piecetext_buffers` row.
        fn put_buffer_meta(&mut self, buffer_id: i64, len_bytes: u32, author_id: i64) {
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_TABLE),
                stored_str(TABLE),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_ROW_ID),
                stored_i64(ROW_ID),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_COLUMN),
                stored_str(COLUMN),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, "author_id"),
                stored_i64(author_id),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, "len_bytes"),
                stored_i64(len_bytes as i64),
            );
        }

        fn setup_base(&mut self) {
            self.put(column_key(USERS_TABLE, UID as i64, "status"), stored_i64(1));
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
                0i64.to_be_bytes().to_vec(),
            );
            self.put(
                piece_coords_tail_key(LIST_NUMBER),
                0i64.to_be_bytes().to_vec(),
            );
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
                    let end = prefix_successor(prefix);
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

    fn stored_str(value: &str) -> Vec<u8> {
        value_to_bytes(&serde_json::Value::String(value.to_string())).unwrap()
    }

    fn envelope() -> PieceTextEditEnvelopeV1 {
        envelope_with_ops(vec![PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: InsertedBufferManifest {
                len_bytes: 4,
                ciphertext_len: 3,
                ciphertext_value_hash: [0xAB; 32],
            },
        }])
    }

    fn envelope_with_ops(ops: Vec<PieceTextEditItemManifest>) -> PieceTextEditEnvelopeV1 {
        PieceTextEditEnvelopeV1 {
            version: PIECE_TEXT_ENVELOPE_VERSION_V1,
            op_id: [9u8; 16],
            address: PieceTextAddress {
                table: TABLE.to_string(),
                row_id: ROW_ID,
                column: COLUMN.to_string(),
            },
            edit: PieceTextEditManifest { ops },
        }
    }

    fn insert_item(at: BufferCoord, len_bytes: u32, marker: u8) -> PieceTextEditItemManifest {
        PieceTextEditItemManifest::Insert {
            at,
            inserted: InsertedBufferManifest {
                len_bytes,
                ciphertext_len: len_bytes + 16,
                ciphertext_value_hash: [marker; 32],
            },
        }
    }

    fn entry(env: &PieceTextEditEnvelopeV1) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: UID,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::PieceTextEdit,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![env.changelog_entry_kv().unwrap()],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: Vec::new(),
        }
    }

    fn seed_piece_state(
        reader: &mut FakeReader,
        rows: &[PieceRow],
        head_id: i64,
        tail_id: i64,
        pre_piece_next_id: i64,
        pre_buffers_next_id: i64,
        buffer_len_bytes: u32,
    ) {
        for row in rows {
            reader.put_piece_row(row);
        }
        reader.put_buffer_meta(1, buffer_len_bytes, UID as i64);
        reader.put(
            piece_coords_head_key(LIST_NUMBER),
            head_id.to_be_bytes().to_vec(),
        );
        reader.put(
            piece_coords_tail_key(LIST_NUMBER),
            tail_id.to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(PIECE_COORDS_TABLE),
            pre_piece_next_id.to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(BUFFERS_TABLE),
            pre_buffers_next_id.to_be_bytes().to_vec(),
        );
    }

    fn piece_row(
        id: i64,
        prev_id: i64,
        next_id: i64,
        start_byte: u32,
        len_bytes: u32,
        tombstone: bool,
    ) -> PieceRow {
        piece_row_buf(id, prev_id, next_id, 1, start_byte, len_bytes, tombstone)
    }

    #[allow(clippy::too_many_arguments)]
    fn piece_row_buf(
        id: i64,
        prev_id: i64,
        next_id: i64,
        buffer_id: i64,
        start_byte: u32,
        len_bytes: u32,
        tombstone: bool,
    ) -> PieceRow {
        PieceRow {
            id,
            list_number: LIST_NUMBER,
            prev_id,
            next_id,
            coord: PieceCoord {
                buffer_id,
                start_byte,
                len_bytes,
                tombstone,
            },
        }
    }

    /// Seed a multi-buffer document: each row, each buffer's owner/len metadata,
    /// and the head/tail/next-id keys. `buffers` is `(buffer_id, len_bytes)`.
    /// Use this where pieces span more than the single buffer 1 that
    /// [`seed_piece_state`] assumes.
    fn seed_doc(
        reader: &mut FakeReader,
        rows: &[PieceRow],
        buffers: &[(i64, u32)],
        head_id: i64,
        tail_id: i64,
        pre_piece_next_id: i64,
        pre_buffers_next_id: i64,
    ) {
        for row in rows {
            reader.put_piece_row(row);
        }
        for (id, len) in buffers {
            reader.put_buffer_meta(*id, *len, UID as i64);
        }
        reader.put(
            piece_coords_head_key(LIST_NUMBER),
            head_id.to_be_bytes().to_vec(),
        );
        reader.put(
            piece_coords_tail_key(LIST_NUMBER),
            tail_id.to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(PIECE_COORDS_TABLE),
            pre_piece_next_id.to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(BUFFERS_TABLE),
            pre_buffers_next_id.to_be_bytes().to_vec(),
        );
    }

    /// True if `ops` writes any column of `_piecetext_pieces` row `id` (used to
    /// assert a row was *not* created/touched).
    fn writes_piece_row(ops: &[BatchOp], id: i64) -> bool {
        ops.iter().any(|op| {
            op.key() == column_key(PIECE_COORDS_TABLE, id, PIECE_COORDS_COL_LIST_NUMBER)
                || op.key() == column_key(PIECE_COORDS_TABLE, id, PIECE_COORDS_COL_TOMBSTONE)
                || op.key() == column_key(PIECE_COORDS_TABLE, id, PIECE_COORDS_COL_NEXT_ID)
                || op.key() == column_key(PIECE_COORDS_TABLE, id, PIECE_COORDS_COL_PREV_ID)
        })
    }

    fn verified_write_ops(env: &PieceTextEditEnvelopeV1, reader: &mut FakeReader) -> Vec<BatchOp> {
        let result = PieceTextEditOp::extract_and_validate(
            &entry(env),
            reader,
            &OpContext::for_change_id(1),
        )
        .unwrap();
        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        ops.clone()
    }

    fn put_value(ops: &[BatchOp], key: Vec<u8>) -> Vec<u8> {
        ops.iter()
            .find_map(|op| match op {
                BatchOp::Put { key: k, value } if k == &key => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing put for key {}", hex::encode(&key)))
    }

    fn assert_stored_i64_put(ops: &[BatchOp], key: Vec<u8>, expected: i64) {
        assert_eq!(put_value(ops, key), stored_i64(expected));
    }

    fn assert_raw_i64_put(ops: &[BatchOp], key: Vec<u8>, expected: i64) {
        assert_eq!(put_value(ops, key), expected.to_be_bytes().to_vec());
    }

    #[test]
    fn piece_text_edit_op_accepts_insert_into_empty_document() {
        let env = envelope();
        let mut reader = FakeReader::default();
        reader.setup_base();

        let result = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap();

        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        assert!(ops.iter().any(|op| {
            matches!(
                op,
                BatchOp::Put { key, value }
                    if key == &piece_coords_head_key(LIST_NUMBER)
                        && value == &1i64.to_be_bytes().to_vec()
            )
        }));
        assert!(ops.iter().any(|op| {
            matches!(
                op,
                BatchOp::Put { key, value }
                    if key == &column_key(BUFFERS_TABLE, 1, "contents")
                        && value == &vec![0xAB; 32]
            )
        }));
    }

    #[test]
    fn piece_text_edit_op_appends_after_existing_piece() {
        let env = envelope_with_ops(vec![insert_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            4,
            0xBB,
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 4, false)],
            1,
            1,
            2,
            2,
            4,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            0,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_BUFFER_ID),
            2,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 2);
        assert_eq!(
            put_value(&ops, column_key(BUFFERS_TABLE, 2, "contents")),
            vec![0xBB; 32]
        );
    }

    #[test]
    fn piece_text_edit_op_splits_insert_inside_a_piece() {
        let env = envelope_with_ops(vec![insert_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            4,
            0xCC,
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 8, false)],
            1,
            1,
            2,
            2,
            8,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_BUFFER_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_PREV_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_NEXT_ID),
            0,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_BUFFER_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 3);
    }

    #[test]
    fn piece_text_edit_op_same_coordinate_inserts_render_newest_first() {
        let env = envelope_with_ops(vec![
            insert_item(BufferCoord::DOCUMENT_START, 4, 0x01),
            insert_item(BufferCoord::DOCUMENT_START, 4, 0x02),
            insert_item(BufferCoord::DOCUMENT_START, 4, 0x03),
        ]);
        let mut reader = FakeReader::default();
        reader.setup_base();

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_PREV_ID),
            0,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_PREV_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            0,
        );
        assert_raw_i64_put(&ops, piece_coords_head_key(LIST_NUMBER), 3);
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 1);
    }

    #[test]
    fn piece_text_edit_op_insert_inside_tombstone_back_clamps_to_live_predecessor() {
        let env = envelope_with_ops(vec![insert_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 8,
            },
            4,
            0xDD,
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[
                piece_row(1, 0, 2, 0, 4, false),
                piece_row(2, 1, 3, 4, 4, true),
                piece_row(3, 2, 0, 8, 4, false),
            ],
            1,
            3,
            4,
            2,
            12,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            4,
        );
    }

    #[test]
    fn piece_text_edit_op_insert_after_row_changed_earlier_in_same_edit() {
        let env = envelope_with_ops(vec![
            insert_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 4,
                },
                4,
                0x11,
            ),
            insert_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 4,
                },
                4,
                0x22,
            ),
        ]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 8, false)],
            1,
            1,
            2,
            2,
            8,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_BUFFER_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_PREV_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_NEXT_ID),
            0,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 3);
    }

    fn delete_item(start: BufferCoord, end: BufferCoord) -> PieceTextEditItemManifest {
        PieceTextEditItemManifest::Delete { start, end }
    }

    #[test]
    fn piece_text_edit_op_deletes_whole_piece_flips_tombstone() {
        // Single live piece, buffer 1 [0,4). Deleting its whole range tombstones
        // it in place with no new rows and no adjacency changes.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 0,
            },
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 4, false)],
            1,
            1,
            2,
            2,
            4,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        // No second row is created (the row is only tombstoned), so nothing
        // writes row id 2's columns.
        assert!(!ops.iter().any(|op| {
            op.key() == column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LIST_NUMBER)
        }));
    }

    #[test]
    fn piece_text_edit_op_ragged_left_delete_splits_piece() {
        // Buffer 1 [0,12). Delete [4,12): the original row shrinks to its live
        // [0,4) prefix and a new tombstone row (id 2) covers the deleted suffix.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            BufferCoord {
                buffer_id: 1,
                byte_pos: 12,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 12, false)],
            1,
            1,
            2,
            2,
            12,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // Original row shrinks to len 4 and points at the new tombstone row.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        // New tombstone suffix row [4,12).
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LEN_BYTES),
            8,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            0,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 2);
    }

    #[test]
    fn piece_text_edit_op_rejects_inverted_delete_range() {
        // Delete start (byte 8) resolves strictly after the end (byte 4).
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 8,
            },
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 12, false)],
            1,
            1,
            2,
            2,
            12,
        );

        let err = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .expect_err("inverted delete range must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("delete start resolved past delete end"),
            "{msg}"
        );
    }

    #[test]
    fn piece_text_edit_op_ragged_center_delete_splits_piece() {
        // Buffer 1 [0,12). Delete [4,8): M_deleted (id 2) then R_right (id 3),
        // original row shrinks to its live [0,4) prefix.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            BufferCoord {
                buffer_id: 1,
                byte_pos: 8,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 12, false)],
            1,
            1,
            2,
            2,
            12,
        );

        let ops = verified_write_ops(&env, &mut reader);

        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        // M_deleted [4,8), tombstoned.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_NEXT_ID),
            3,
        );
        // R_right [8,12), live.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_START_BYTE),
            8,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_TOMBSTONE),
            0,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 3);
    }

    #[test]
    fn piece_text_edit_op_ragged_right_delete_splits_piece() {
        // Buffer 1 [0,12). Delete [0,8): left prefix tombstoned in place, live
        // suffix [8,12) becomes a new row (id 2).
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 0,
            },
            BufferCoord {
                buffer_id: 1,
                byte_pos: 8,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 12, false)],
            1,
            1,
            2,
            2,
            12,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // Original row keeps prefix [0,8) and is tombstoned.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            8,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        // New live suffix [8,12).
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_START_BYTE),
            8,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            0,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 2);
    }

    #[test]
    fn piece_text_edit_op_deletes_across_multiple_pieces() {
        // A(buf1 [0,8)) -> B(buf2 [0,4)) -> C(buf3 [0,8)). Delete from middle of
        // A (byte 4) to middle of C (byte 4): ML_deleted (id 4), MR_right (id 5),
        // B tombstoned in place.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            BufferCoord {
                buffer_id: 3,
                byte_pos: 4,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_doc(
            &mut reader,
            &[
                piece_row_buf(1, 0, 2, 1, 0, 8, false),
                piece_row_buf(2, 1, 3, 2, 0, 4, false),
                piece_row_buf(3, 2, 0, 3, 0, 8, false),
            ],
            &[(1, 8), (2, 4), (3, 8)],
            1,
            3,
            4,
            4,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // A shrinks to its live [0,4) prefix, points at ML.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            4,
        );
        // ML_deleted: tombstoned right suffix of A, buffer 1 [4,8).
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_BUFFER_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        // B wholly tombstoned, prev rewired to ML.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            4,
        );
        // MR_right: live left suffix of C, buffer 3 [4,8).
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 5, PIECE_COORDS_COL_BUFFER_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 5, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 5, PIECE_COORDS_COL_TOMBSTONE),
            0,
        );
        // C shrinks to [0,4), tombstoned, points at MR.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_NEXT_ID),
            5,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 5);
    }

    #[test]
    fn piece_text_edit_op_overlapping_sequential_deletes_idempotent_in_overlap() {
        // Op 1 deletes A entirely; op 2 runs from inside the now-tombstoned A to
        // the middle of C. A tombstones exactly once, B wholly, C is ragged-right.
        let env = envelope_with_ops(vec![
            delete_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 0,
                },
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 8,
                },
            ),
            delete_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 4,
                },
                BufferCoord {
                    buffer_id: 3,
                    byte_pos: 4,
                },
            ),
        ]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_doc(
            &mut reader,
            &[
                piece_row_buf(1, 0, 2, 1, 0, 8, false),
                piece_row_buf(2, 1, 3, 2, 0, 4, false),
                piece_row_buf(3, 2, 0, 3, 0, 8, false),
            ],
            &[(1, 8), (2, 4), (3, 8)],
            1,
            3,
            4,
            4,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // A tombstoned exactly once: coord untouched apart from the flag, no
        // second row split off it.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LEN_BYTES),
            8,
        );
        // B wholly tombstoned.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        // C ragged-right: shrinks to [0,4) tombstoned, new live suffix row id 4.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_LEN_BYTES),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 3, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_BUFFER_ID),
            3,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_START_BYTE),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_TOMBSTONE),
            0,
        );
        // No fifth row: the overlap region is not re-split.
        assert!(!writes_piece_row(&ops, 5));
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 4);
    }

    #[test]
    fn piece_text_edit_op_delete_then_insert_at_deleted_boundary() {
        // Buffer 1 [0,12). Delete [4,8) (P=1, M_deleted=2, R_right=3), then
        // insert at byte 4: N (id 4) splices after P, before M_deleted, in a
        // freshly allocated buffer (id 2).
        let env = envelope_with_ops(vec![
            delete_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 4,
                },
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 8,
                },
            ),
            insert_item(
                BufferCoord {
                    buffer_id: 1,
                    byte_pos: 4,
                },
                4,
                0xFE,
            ),
        ]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_piece_state(
            &mut reader,
            &[piece_row(1, 0, 0, 0, 12, false)],
            1,
            1,
            2,
            2,
            12,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // N (id 4) spliced after P, before M_deleted, in new buffer 2.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_BUFFER_ID),
            2,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_PREV_ID),
            1,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 4, PIECE_COORDS_COL_NEXT_ID),
            2,
        );
        // P now points at N; M_deleted's prev is rewired to N.
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_NEXT_ID),
            4,
        );
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_PREV_ID),
            4,
        );
        // The inserted buffer's contents hash is materialised.
        assert_eq!(
            put_value(&ops, column_key(BUFFERS_TABLE, 2, "contents")),
            vec![0xFE; 32]
        );
        assert_raw_i64_put(&ops, piece_coords_tail_key(LIST_NUMBER), 3);
    }

    #[test]
    fn piece_text_edit_op_delete_inside_all_tombstoned_chain_is_noop() {
        // Both rows already tombstoned (buffer 5 [0,8) and [8,16)). DeleteStart
        // clamps to AfterTail, DeleteEnd to BeforeHead, and the all-tombstoned
        // chain makes them compare equal -> no writes at all.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            BufferCoord {
                buffer_id: 5,
                byte_pos: 12,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_doc(
            &mut reader,
            &[
                piece_row_buf(1, 0, 2, 5, 0, 8, true),
                piece_row_buf(2, 1, 0, 5, 8, 8, true),
            ],
            &[(5, 16)],
            1,
            2,
            3,
            6,
        );

        let ops = verified_write_ops(&env, &mut reader);
        assert!(
            ops.is_empty(),
            "all-tombstoned delete must be a no-op: {ops:?}"
        );
    }

    #[test]
    fn piece_text_edit_op_delete_clamps_through_tombstone_runs() {
        // A(buf1 [0,8), tomb) -> B(buf2 [0,4), live) -> C(buf3 [0,8), tomb).
        // Delete from inside tombstoned A to inside tombstoned C: DeleteStart
        // forward-clamps and DeleteEnd backward-clamps onto B, so only B is
        // tombstoned and no new rows are created.
        let env = envelope_with_ops(vec![delete_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 4,
            },
            BufferCoord {
                buffer_id: 3,
                byte_pos: 4,
            },
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        seed_doc(
            &mut reader,
            &[
                piece_row_buf(1, 0, 2, 1, 0, 8, true),
                piece_row_buf(2, 1, 3, 2, 0, 4, false),
                piece_row_buf(3, 2, 0, 3, 0, 8, true),
            ],
            &[(1, 8), (2, 4), (3, 8)],
            1,
            3,
            4,
            4,
        );

        let ops = verified_write_ops(&env, &mut reader);

        // Only B flips to tombstone; no split rows are created and the chain
        // endpoints are unchanged (so no tail key is rewritten).
        assert_stored_i64_put(
            &ops,
            column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_TOMBSTONE),
            1,
        );
        assert!(!writes_piece_row(&ops, 4));
        assert!(!ops
            .iter()
            .any(|op| op.key() == piece_coords_tail_key(LIST_NUMBER)));
    }

    /// Stage 0 guard (PLAN_PIECE_SMALL_CLEANUP): planning a `PieceTextEdit` over
    /// a large document must resolve its coordinates through indexed point /
    /// `buffer_id` reads — never a range read over the document's whole
    /// `_piecetext_pieces.list_number` index.
    #[test]
    fn piece_text_edit_op_uses_indexed_coord_reads_not_full_list_snapshot() {
        // A valid, non-trivial single-buffer document: PIECES live rows chained
        // head(1) -> ... -> tail(PIECES), buffer 1 spanning [0, 4 * PIECES).
        const PIECES: i64 = 64;

        let mut reader = FakeReader::default();
        reader.setup_base();
        for id in 1..=PIECES {
            let row = PieceRow {
                id,
                list_number: LIST_NUMBER,
                prev_id: if id == 1 { 0 } else { id - 1 },
                next_id: if id == PIECES { 0 } else { id + 1 },
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: ((id - 1) * 4) as u32,
                    len_bytes: 4,
                    tombstone: false,
                },
            };
            reader.put_piece_row(&row);
        }
        reader.put_buffer_meta(1, (PIECES * 4) as u32, UID as i64);
        reader.put(
            piece_coords_head_key(LIST_NUMBER),
            1i64.to_be_bytes().to_vec(),
        );
        reader.put(
            piece_coords_tail_key(LIST_NUMBER),
            PIECES.to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(PIECE_COORDS_TABLE),
            (PIECES + 1).to_be_bytes().to_vec(),
        );
        reader.put(
            schema_next_id_key(BUFFERS_TABLE),
            2i64.to_be_bytes().to_vec(),
        );

        // A well-formed, aligned insert at the document head: this must verify
        // against the seeded document, so any failure here is a setup bug, not
        // the behavior under test.
        let env = envelope();
        let result = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .expect("edit over a valid document must verify");
        let TraceStep::Write(_) = &result.write_steps[0] else {
            panic!("expected write step");
        };

        // The behavior under test: no read may scan the whole document by
        // range/prefix over the `_piecetext_pieces.list_number` index.
        let list_index_prefix =
            index_column_prefix(PIECE_COORDS_TABLE, PIECE_COORDS_COL_LIST_NUMBER);
        let offending: Vec<&ReadOp> = reader
            .reads
            .iter()
            .filter(|op| match op {
                ReadOp::Range { start, .. } => start.starts_with(&list_index_prefix),
                ReadOp::Prefix(prefix) => prefix.starts_with(&list_index_prefix),
                ReadOp::Key(_) => false,
            })
            .collect();
        assert!(
            offending.is_empty(),
            "PieceTextEditOp must not range-read the whole \
             _piecetext_pieces.list_number index to plan an edit; found {} such scan(s): {offending:?}",
            offending.len()
        );
    }

    #[test]
    fn piece_text_edit_op_rejects_parent_mapping_mismatch() {
        let env = envelope();
        let mut reader = FakeReader::default();
        reader.setup_base();
        reader.put(
            piece_coords_parent_key(LIST_NUMBER),
            encode_list_parent(TABLE, ROW_ID + 1, COLUMN),
        );

        let err = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("piece_coords_parent_key"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_cross_list_buffer_index_row() {
        let env = envelope_with_ops(vec![insert_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 0,
            },
            4,
            0xCC,
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        let index = index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 1, 99).unwrap();
        reader.put(index, row_id_to_bytes(99).to_vec());
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_LIST_NUMBER),
            stored_i64(LIST_NUMBER + 1),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_PREV_ID),
            stored_i64(0),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_NEXT_ID),
            stored_i64(0),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_BUFFER_ID),
            stored_i64(1),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_START_BYTE),
            stored_i64(0),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_LEN_BYTES),
            stored_i64(4),
        );
        reader.put(
            column_key(PIECE_COORDS_TABLE, 99, PIECE_COORDS_COL_TOMBSTONE),
            stored_i64(0),
        );

        let err = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("belongs to list"), "{err}");
    }

    fn delete_envelope(start: BufferCoord, end: BufferCoord) -> PieceTextEditEnvelopeV1 {
        PieceTextEditEnvelopeV1 {
            version: PIECE_TEXT_ENVELOPE_VERSION_V1,
            op_id: [9u8; 16],
            address: PieceTextAddress {
                table: TABLE.to_string(),
                row_id: ROW_ID,
                column: COLUMN.to_string(),
            },
            edit: PieceTextEditManifest {
                ops: vec![PieceTextEditItemManifest::Delete { start, end }],
            },
        }
    }

    fn expect_rejected(env: &PieceTextEditEnvelopeV1) -> String {
        let mut reader = FakeReader::default();
        reader.setup_base();
        PieceTextEditOp::extract_and_validate(
            &entry(env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn piece_text_edit_op_rejects_unaligned_insert_at() {
        let mut env = envelope();
        if let PieceTextEditItemManifest::Insert { at, .. } = &mut env.edit.ops[0] {
            *at = BufferCoord {
                buffer_id: 5,
                byte_pos: 2,
            };
        }
        let err = expect_rejected(&env);
        assert!(err.contains("multiple of 4"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_unaligned_inserted_len_bytes() {
        let mut env = envelope();
        if let PieceTextEditItemManifest::Insert { inserted, .. } = &mut env.edit.ops[0] {
            inserted.len_bytes = 6;
        }
        let err = expect_rejected(&env);
        assert!(err.contains("multiple of 4"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_unaligned_delete_start() {
        let env = delete_envelope(
            BufferCoord {
                buffer_id: 5,
                byte_pos: 2,
            },
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
        );
        let err = expect_rejected(&env);
        assert!(err.contains("multiple of 4"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_unaligned_delete_end() {
        let env = delete_envelope(
            BufferCoord::DOCUMENT_START,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 6,
            },
        );
        let err = expect_rejected(&env);
        assert!(err.contains("multiple of 4"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_unaligned_preexisting_row() {
        // Aligned insert at a persistent coordinate, but the indexed candidate
        // row carries a coord that predates alignment enforcement (len_bytes =
        // 5). The row is reached through `buffer_id`, so the authenticated row
        // read must reject it.
        let env = envelope_with_ops(vec![insert_item(
            BufferCoord {
                buffer_id: 1,
                byte_pos: 0,
            },
            4,
            0xCC,
        )]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        let index = index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 1, 77).unwrap();
        reader.put(index, row_id_to_bytes(77).to_vec());
        for (col, val) in [
            (PIECE_COORDS_COL_LIST_NUMBER, LIST_NUMBER),
            (PIECE_COORDS_COL_PREV_ID, 0),
            (PIECE_COORDS_COL_NEXT_ID, 0),
            (PIECE_COORDS_COL_BUFFER_ID, 1),
            (PIECE_COORDS_COL_START_BYTE, 0),
            (PIECE_COORDS_COL_LEN_BYTES, 5),
            (PIECE_COORDS_COL_TOMBSTONE, 0),
        ] {
            reader.put(column_key(PIECE_COORDS_TABLE, 77, col), stored_i64(val));
        }

        let err = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("UTF-32 aligned"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_rejects_duplicate_materialised_write_keys() {
        let output = crate::piece_text_planner::PlannerOutput {
            piece_updates: vec![
                crate::piece_text_planner::PieceRowUpdate {
                    id: 77,
                    prev_id: Some(1),
                    next_id: None,
                    coord: None,
                },
                crate::piece_text_planner::PieceRowUpdate {
                    id: 77,
                    prev_id: Some(2),
                    next_id: None,
                    coord: None,
                },
            ],
            ..Default::default()
        };
        let original_coords = BTreeMap::new();

        let err = materialise_planner_output(&envelope(), LIST_NUMBER, &output, &original_coords)
            .unwrap_err()
            .to_string();

        assert!(err.contains("duplicate write key"), "{err}");
    }

    #[test]
    fn piece_text_edit_op_accepts_aligned_multiscalar_insert() {
        // Two UTF-32 scalars (8 bytes) inserted into an empty document: a
        // well-formed, fully-aligned edit must verify and write the head.
        let mut env = envelope();
        if let PieceTextEditItemManifest::Insert { inserted, .. } = &mut env.edit.ops[0] {
            inserted.len_bytes = 8;
        }
        let mut reader = FakeReader::default();
        reader.setup_base();

        let result = PieceTextEditOp::extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap();

        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        assert!(ops.iter().any(|op| matches!(
            op,
            BatchOp::Put { key, .. } if key == &piece_coords_head_key(LIST_NUMBER)
        )));
    }

    #[test]
    fn piece_text_edit_op_reports_metrics_for_empty_document() {
        let env = envelope();
        let mut reader = FakeReader::default();
        reader.setup_base();

        let (_, metrics) = PieceTextEditOp::extract_and_validate_with_metrics(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(1),
        )
        .unwrap();

        assert_eq!(metrics.piece_rows_read, 0);
        assert_eq!(metrics.buffer_rows_read, 0);
        assert_eq!(metrics.inserted_piece_rows, 1);
        assert_eq!(metrics.inserted_buffer_rows, 1);
        assert!(metrics.write_ops > 0);
    }
}
