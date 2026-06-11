//! Authenticated `_piecetext_pieces.buffer_id` coordinate lookup.
//!
//! This module resolves one persistent [`BufferCoord`] through `OpReader`
//! using the `_piecetext_pieces.buffer_id` secondary index, reads candidate rows by
//! point key, applies the predecessor boundary tie-break, and walks tombstones
//! in the caller-requested clamp direction.

use crate::changelog::ChangelogError;
use crate::ops::OpReader;
use crate::piece_text::{BufferCoord, PieceCoord};
use crate::piece_text_planner::{ClampDirection, PieceRow, ResolvePurpose};
use crate::piece_text_resolution::{
    resolve_coord_core, ResolveCoreResult, ResolveEndpoint, ResolveSource,
};
use crate::{BatchOp, ReadOp};
use encrypted_spaces_storage_encoding::keys::{
    column_key, index_key, index_value_prefix, parse_key, piece_coords_head_key,
    piece_coords_tail_key, row_id_to_bytes, ParsedKey, BUFFERS_TABLE, PIECE_COORDS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::bytes_to_value;
use encrypted_spaces_storage_encoding::TupleElement;
use ffproof_tracer_shared::prefix_successor;

pub const PIECE_COORDS_COL_LIST_NUMBER: &str = "list_number";
pub const PIECE_COORDS_COL_PREV_ID: &str = "prev_id";
pub const PIECE_COORDS_COL_NEXT_ID: &str = "next_id";
pub const PIECE_COORDS_COL_BUFFER_ID: &str = "buffer_id";
pub const PIECE_COORDS_COL_START_BYTE: &str = "start_byte";
pub const PIECE_COORDS_COL_LEN_BYTES: &str = "len_bytes";
pub const PIECE_COORDS_COL_TOMBSTONE: &str = "tombstone";

pub const BUFFERS_COL_OWNER_COLUMN: &str = "owner_column";
pub const BUFFERS_COL_OWNER_ROW_ID: &str = "owner_row_id";
pub const BUFFERS_COL_OWNER_TABLE: &str = "owner_table";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexedResolveResult {
    /// `BufferCoord::DOCUMENT_START`, resolved by authenticating the list head.
    DocumentStart { head_id: i64 },
    /// A live row matched directly. `offset = coord.byte_pos - start_byte`.
    InRow { row: PieceRow, offset: u32 },
    /// A tombstone run clamped to a live row in the purpose-specific direction.
    ClampedToRow {
        row: PieceRow,
        direction: ClampDirection,
        hops: u32,
    },
    /// A backward tombstone clamp reached document start.
    ClampedBeforeHead {
        head_id: i64,
        start_row_id: i64,
        hops: u32,
    },
    /// A forward tombstone clamp reached document end.
    ClampedAfterTail {
        tail_id: i64,
        start_row_id: i64,
        hops: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolveCoordMetrics {
    /// Number of `_piecetext_pieces.buffer_id` index entries returned for this
    /// coordinate. This is the `K_per_buffer` term in the piece-text proof
    /// cost model. `DOCUMENT_START` uses no index lookup and reports `0`.
    pub k_per_buffer: usize,
    /// Number of tombstoned rows skipped by purpose-specific clamping.
    pub tombstone_clamp_hops: u32,
}

/// Resolve a persistent byte coordinate through the authenticated
/// `_piecetext_pieces.buffer_id` index.
pub fn resolve_coord(
    reader: &mut dyn OpReader,
    list_number: i64,
    coord: BufferCoord,
    purpose: ResolvePurpose,
) -> Result<IndexedResolveResult, ChangelogError> {
    resolve_coord_with_metrics(reader, list_number, coord, purpose).map(|(result, _)| result)
}

/// Resolve a coordinate and return the observable lookup-window metrics for
/// hardening / operations logs.
pub fn resolve_coord_with_metrics(
    reader: &mut dyn OpReader,
    list_number: i64,
    coord: BufferCoord,
    purpose: ResolvePurpose,
) -> Result<(IndexedResolveResult, ResolveCoordMetrics), ChangelogError> {
    // Enforce the coord invariant boundary on the public API too. The
    // load-bearing edit path validates envelope endpoints up front, but this
    // function is `pub`; without this a future caller could resolve a position
    // inside a UTF-32 scalar (e.g. byte_pos=1), re-opening the byte-coordinate
    // hazard. `validate_shape` accepts DOCUMENT_START and rejects buffer_id < 0
    // and any non-4-aligned byte_pos.
    coord.validate_shape()?;
    let output = {
        let mut source = IndexedResolveSource {
            reader,
            list_number,
        };
        resolve_coord_core(&mut source, coord, purpose)?
    };
    let result = indexed_result_from_core(output.result);
    let metrics = ResolveCoordMetrics {
        k_per_buffer: output.candidate_count,
        tombstone_clamp_hops: tombstone_clamp_hops(&result),
    };
    Ok((result, metrics))
}

struct IndexedResolveSource<'a> {
    reader: &'a mut dyn OpReader,
    list_number: i64,
}

impl ResolveSource for IndexedResolveSource<'_> {
    type Error = ChangelogError;

    fn list_number(&self) -> i64 {
        self.list_number
    }

    fn candidate_row_ids(&mut self, buffer_id: i64) -> Result<Vec<i64>, Self::Error> {
        read_candidate_row_ids(self.reader, buffer_id)
    }

    fn read_row(&mut self, row_id: i64) -> Result<PieceRow, Self::Error> {
        read_aligned_piece_coords_row(self.reader, row_id)
    }

    fn read_endpoint(&mut self, endpoint: ResolveEndpoint) -> Result<i64, Self::Error> {
        read_piece_coords_endpoint(self.reader, self.list_number, endpoint)
    }

    fn invalid_coordinate(&self, message: String) -> Self::Error {
        ChangelogError::Generic(message)
    }

    fn unknown_coordinate(
        &self,
        coord: BufferCoord,
        _purpose: ResolvePurpose,
        _reason: String,
    ) -> Self::Error {
        ChangelogError::Generic(format!(
            "unknown piece-text coordinate: no row covers buffer_id={} byte_pos={}",
            coord.buffer_id, coord.byte_pos
        ))
    }

    fn invariant(&self, message: String) -> Self::Error {
        ChangelogError::Generic(message)
    }
}

fn indexed_result_from_core(result: ResolveCoreResult) -> IndexedResolveResult {
    match result {
        ResolveCoreResult::DocumentStart { head_id } => {
            IndexedResolveResult::DocumentStart { head_id }
        }
        ResolveCoreResult::InRow { row, offset } => IndexedResolveResult::InRow { row, offset },
        ResolveCoreResult::ClampedToRow {
            row,
            direction,
            hops,
            ..
        } => IndexedResolveResult::ClampedToRow {
            row,
            direction,
            hops,
        },
        ResolveCoreResult::ClampedBeforeHead {
            head_id,
            start_row_id,
            hops,
            ..
        } => IndexedResolveResult::ClampedBeforeHead {
            head_id,
            start_row_id,
            hops,
        },
        ResolveCoreResult::ClampedAfterTail {
            tail_id,
            start_row_id,
            hops,
            ..
        } => IndexedResolveResult::ClampedAfterTail {
            tail_id,
            start_row_id,
            hops,
        },
    }
}

fn tombstone_clamp_hops(result: &IndexedResolveResult) -> u32 {
    match result {
        IndexedResolveResult::ClampedToRow { hops, .. }
        | IndexedResolveResult::ClampedBeforeHead { hops, .. }
        | IndexedResolveResult::ClampedAfterTail { hops, .. } => *hops,
        IndexedResolveResult::DocumentStart { .. } | IndexedResolveResult::InRow { .. } => 0,
    }
}

/// Authenticate the `_piecetext_pieces.buffer_id` secondary index for one
/// buffer and return its candidate `_piecetext_pieces` row ids.
///
/// Shared by the single-coordinate [`resolve_coord`] path and the indexed
/// overlay edit planner ([`crate::piece_text_overlay`]) so both authenticate
/// the index the same way. Each returned entry is spec-checked: it must be an
/// `Index` key for `(_piecetext_pieces, buffer_id, buffer_id)` whose stored
/// value is the entry's own positive `row_id`.
pub(crate) fn read_candidate_row_ids(
    reader: &mut dyn OpReader,
    buffer_id: i64,
) -> Result<Vec<i64>, ChangelogError> {
    let prefix = index_value_prefix(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, buffer_id)
        .map_err(|e| {
            ChangelogError::Generic(format!("failed to build buffer_id index prefix: {e}"))
        })?;
    let end = prefix_successor(&prefix).ok_or_else(|| {
        ChangelogError::Generic("buffer_id index prefix has no successor".to_string())
    })?;
    let candidates = reader.read(ReadOp::Range { start: prefix, end })?;
    let mut row_ids = Vec::with_capacity(candidates.results.len());
    for (index_entry_key, index_entry_value) in &candidates.results {
        row_ids.push(decode_piece_coords_buffer_index_entry(
            index_entry_key,
            index_entry_value,
            buffer_id,
        )?);
    }
    Ok(row_ids)
}

/// Read one `_piecetext_pieces` row by point keys.
pub fn read_piece_coords_row(
    reader: &mut dyn OpReader,
    row_id: i64,
) -> Result<PieceRow, ChangelogError> {
    if row_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_pieces row_id must be positive, got {row_id}"
        )));
    }

    let list_number = read_i64_column(reader, row_id, PIECE_COORDS_COL_LIST_NUMBER)?;
    let prev_id = read_i64_column(reader, row_id, PIECE_COORDS_COL_PREV_ID)?;
    let next_id = read_i64_column(reader, row_id, PIECE_COORDS_COL_NEXT_ID)?;
    let buffer_id = read_i64_column(reader, row_id, PIECE_COORDS_COL_BUFFER_ID)?;
    let start_byte = read_u32_column(reader, row_id, PIECE_COORDS_COL_START_BYTE)?;
    let len_bytes = read_u32_column(reader, row_id, PIECE_COORDS_COL_LEN_BYTES)?;
    if len_bytes == 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_pieces row {row_id} has zero len_bytes"
        )));
    }
    let tombstone_raw = read_i64_column(reader, row_id, PIECE_COORDS_COL_TOMBSTONE)?;
    let tombstone = match tombstone_raw {
        0 => false,
        1 => true,
        other => {
            return Err(ChangelogError::Generic(format!(
                "_piecetext_pieces row {row_id} has invalid tombstone value {other}"
            )))
        }
    };
    start_byte.checked_add(len_bytes).ok_or_else(|| {
        ChangelogError::Generic(format!("_piecetext_pieces row {row_id} range overflows"))
    })?;

    Ok(PieceRow {
        id: row_id,
        list_number,
        prev_id,
        next_id,
        coord: PieceCoord {
            buffer_id,
            start_byte,
            len_bytes,
            tombstone,
        },
    })
}

/// Like [`read_piece_coords_row`] but additionally enforces UTF-32 alignment on
/// the row's range (defense-in-depth range validation). The resolver walks and
/// extends byte ranges, so it must never trust a misaligned pre-existing row.
pub(crate) fn read_aligned_piece_coords_row(
    reader: &mut dyn OpReader,
    row_id: i64,
) -> Result<PieceRow, ChangelogError> {
    let row = read_piece_coords_row(reader, row_id)?;
    row.coord
        .validate_utf32_alignment()
        .map_err(|e| ChangelogError::Generic(format!("_piecetext_pieces row {row_id}: {e}")))?;
    Ok(row)
}

/// Index puts required for one newly inserted `_piecetext_pieces` row.
pub fn piece_coords_insert_index_puts(
    row_id: i64,
    list_number: i64,
    buffer_id: i64,
) -> Result<Vec<BatchOp>, ChangelogError> {
    if row_id <= 0 || list_number <= 0 || buffer_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_pieces index puts require positive row_id/list_number/buffer_id, got row_id={row_id}, list_number={list_number}, buffer_id={buffer_id}"
        )));
    }
    Ok(vec![
        index_put(
            PIECE_COORDS_TABLE,
            PIECE_COORDS_COL_BUFFER_ID,
            buffer_id,
            row_id,
        )?,
        index_put(
            PIECE_COORDS_TABLE,
            PIECE_COORDS_COL_LIST_NUMBER,
            list_number,
            row_id,
        )?,
    ])
}

/// Index deletes required for one removed `_piecetext_pieces` row.
pub fn piece_coords_delete_index_deletes(
    row_id: i64,
    list_number: i64,
    buffer_id: i64,
) -> Result<Vec<BatchOp>, ChangelogError> {
    if row_id <= 0 || list_number <= 0 || buffer_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_pieces index deletes require positive row_id/list_number/buffer_id, got row_id={row_id}, list_number={list_number}, buffer_id={buffer_id}"
        )));
    }
    Ok(vec![
        index_delete(
            PIECE_COORDS_TABLE,
            PIECE_COORDS_COL_BUFFER_ID,
            buffer_id,
            row_id,
        )?,
        index_delete(
            PIECE_COORDS_TABLE,
            PIECE_COORDS_COL_LIST_NUMBER,
            list_number,
            row_id,
        )?,
    ])
}

/// Index puts required for one newly inserted `_piecetext_buffers` row.
pub fn buffers_insert_index_puts(
    row_id: i64,
    owner_table: &str,
    owner_row_id: i64,
    owner_column: &str,
) -> Result<Vec<BatchOp>, ChangelogError> {
    if row_id <= 0 || owner_row_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_buffers index puts require positive row_id and owner_row_id, got row_id={row_id}, owner_row_id={owner_row_id}"
        )));
    }
    Ok(vec![
        index_put(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_COLUMN,
            owner_column.to_string(),
            row_id,
        )?,
        index_put(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_ROW_ID,
            owner_row_id,
            row_id,
        )?,
        index_put(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_TABLE,
            owner_table.to_string(),
            row_id,
        )?,
    ])
}

/// Index deletes required for one removed `_piecetext_buffers` row.
pub fn buffers_delete_index_deletes(
    row_id: i64,
    owner_table: &str,
    owner_row_id: i64,
    owner_column: &str,
) -> Result<Vec<BatchOp>, ChangelogError> {
    if row_id <= 0 || owner_row_id <= 0 {
        return Err(ChangelogError::Generic(format!(
            "_piecetext_buffers index deletes require positive row_id and owner_row_id, got row_id={row_id}, owner_row_id={owner_row_id}"
        )));
    }
    Ok(vec![
        index_delete(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_COLUMN,
            owner_column.to_string(),
            row_id,
        )?,
        index_delete(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_ROW_ID,
            owner_row_id,
            row_id,
        )?,
        index_delete(
            BUFFERS_TABLE,
            BUFFERS_COL_OWNER_TABLE,
            owner_table.to_string(),
            row_id,
        )?,
    ])
}

fn decode_piece_coords_buffer_index_entry(
    key: &[u8],
    value: &[u8],
    expected_buffer_id: i64,
) -> Result<i64, ChangelogError> {
    match parse_key(key) {
        Ok(ParsedKey::Index {
            table,
            column,
            value: index_value,
            row_id,
        }) => {
            if table != PIECE_COORDS_TABLE {
                return Err(ChangelogError::Generic(format!(
                    "buffer_id range returned index for table '{table}', expected '{PIECE_COORDS_TABLE}'"
                )));
            }
            if column != PIECE_COORDS_COL_BUFFER_ID {
                return Err(ChangelogError::Generic(format!(
                    "buffer_id range returned index for column '{column}', expected '{PIECE_COORDS_COL_BUFFER_ID}'"
                )));
            }
            if index_value != TupleElement::Int(expected_buffer_id) {
                return Err(ChangelogError::Generic(format!(
                    "buffer_id range returned index value {:?}, expected {}",
                    index_value, expected_buffer_id
                )));
            }
            let expected_value = row_id_to_bytes(row_id);
            if value != expected_value {
                return Err(ChangelogError::Generic(format!(
                    "buffer_id index entry for row {row_id} has wrong stored row_id value"
                )));
            }
            if row_id <= 0 {
                return Err(ChangelogError::Generic(format!(
                    "buffer_id index entry row_id must be positive, got {row_id}"
                )));
            }
            Ok(row_id)
        }
        Ok(other) => Err(ChangelogError::Generic(format!(
            "buffer_id range returned non-index key: {other:?}"
        ))),
        Err(e) => Err(ChangelogError::Generic(format!(
            "failed to parse buffer_id index key: {e}"
        ))),
    }
}

fn read_i64_column(
    reader: &mut dyn OpReader,
    row_id: i64,
    column: &str,
) -> Result<i64, ChangelogError> {
    let key = column_key(PIECE_COORDS_TABLE, row_id, column);
    let value = read_single_key(
        reader,
        key,
        &format!("_piecetext_pieces[{row_id}].{column}"),
    )?;
    bytes_to_value(&value)
        .map_err(|e| {
            ChangelogError::Generic(format!(
                "failed to decode _piecetext_pieces[{row_id}].{column}: {e}"
            ))
        })?
        .as_i64()
        .ok_or_else(|| {
            ChangelogError::Generic(format!(
                "_piecetext_pieces[{row_id}].{column} is not an integer"
            ))
        })
}

fn read_u32_column(
    reader: &mut dyn OpReader,
    row_id: i64,
    column: &str,
) -> Result<u32, ChangelogError> {
    let value = read_i64_column(reader, row_id, column)?;
    u32::try_from(value).map_err(|_| {
        ChangelogError::Generic(format!(
            "_piecetext_pieces[{row_id}].{column} value {value} is outside u32 range"
        ))
    })
}

fn read_piece_coords_endpoint(
    reader: &mut dyn OpReader,
    list_number: i64,
    endpoint: ResolveEndpoint,
) -> Result<i64, ChangelogError> {
    let (key, label) = match endpoint {
        ResolveEndpoint::Head => (
            piece_coords_head_key(list_number),
            format!("piece_coords_head_key({list_number})"),
        ),
        ResolveEndpoint::Tail => (
            piece_coords_tail_key(list_number),
            format!("piece_coords_tail_key({list_number})"),
        ),
    };
    let value = read_single_key(reader, key, &label)?;
    if value.len() != 8 {
        return Err(ChangelogError::Generic(format!(
            "{label} has invalid length {}, expected 8",
            value.len()
        )));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&value);
    Ok(i64::from_be_bytes(bytes))
}

fn read_single_key(
    reader: &mut dyn OpReader,
    key: Vec<u8>,
    label: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let read = reader.read(ReadOp::Key(key.clone()))?;
    if read.results.len() != 1 {
        return Err(ChangelogError::Generic(format!(
            "{label} read returned {} results, expected 1",
            read.results.len()
        )));
    }
    let (actual_key, value) = &read.results[0];
    if actual_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{label} read returned wrong key: expected {}, got {}",
            hex::encode(&key),
            hex::encode(actual_key)
        )));
    }
    Ok(value.clone())
}

fn index_put<V>(table: &str, column: &str, value: V, row_id: i64) -> Result<BatchOp, ChangelogError>
where
    V: TryInto<TupleElement>,
    V::Error: Into<encrypted_spaces_storage_encoding::TupleConversionError>,
{
    let key = index_key(table, column, value, row_id)
        .map_err(|e| ChangelogError::Generic(format!("failed to build index key: {e}")))?;
    Ok(BatchOp::Put {
        key,
        value: row_id_to_bytes(row_id).to_vec(),
    })
}

fn index_delete<V>(
    table: &str,
    column: &str,
    value: V,
    row_id: i64,
) -> Result<BatchOp, ChangelogError>
where
    V: TryInto<TupleElement>,
    V::Error: Into<encrypted_spaces_storage_encoding::TupleConversionError>,
{
    let key = index_key(table, column, value, row_id)
        .map_err(|e| ChangelogError::Generic(format!("failed to build index key: {e}")))?;
    Ok(BatchOp::Delete { key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::make_index_put;
    use encrypted_spaces_storage_encoding::keys::{index_key, row_id_to_bytes};
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use serde_json::json;
    use std::collections::BTreeMap;

    type ReadResults = Vec<(Vec<u8>, Vec<u8>)>;
    type ReadOverrideMap = BTreeMap<Vec<u8>, ReadResults>;

    #[derive(Default)]
    struct StubReader {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        range_overrides: ReadOverrideMap,
        key_overrides: ReadOverrideMap,
        reads: Vec<ReadOp>,
    }

    impl StubReader {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.kv.insert(key, value);
        }

        fn put_row(&mut self, row: PieceRow) {
            self.put_i64_col(row.id, PIECE_COORDS_COL_LIST_NUMBER, row.list_number);
            self.put_i64_col(row.id, PIECE_COORDS_COL_PREV_ID, row.prev_id);
            self.put_i64_col(row.id, PIECE_COORDS_COL_NEXT_ID, row.next_id);
            self.put_i64_col(row.id, PIECE_COORDS_COL_BUFFER_ID, row.coord.buffer_id);
            self.put_i64_col(
                row.id,
                PIECE_COORDS_COL_START_BYTE,
                row.coord.start_byte as i64,
            );
            self.put_i64_col(
                row.id,
                PIECE_COORDS_COL_LEN_BYTES,
                row.coord.len_bytes as i64,
            );
            self.put_i64_col(
                row.id,
                PIECE_COORDS_COL_TOMBSTONE,
                if row.coord.tombstone { 1 } else { 0 },
            );
        }

        fn put_i64_col(&mut self, row_id: i64, column: &str, value: i64) {
            self.put(
                column_key(PIECE_COORDS_TABLE, row_id, column),
                stored_i64(value),
            );
        }

        fn put_buffer_index(&mut self, buffer_id: i64, row_id: i64) {
            self.put(
                index_key(
                    PIECE_COORDS_TABLE,
                    PIECE_COORDS_COL_BUFFER_ID,
                    buffer_id,
                    row_id,
                )
                .unwrap(),
                row_id_to_bytes(row_id).to_vec(),
            );
        }

        fn put_head(&mut self, list_number: i64, head_id: i64) {
            self.put(
                piece_coords_head_key(list_number),
                head_id.to_be_bytes().to_vec(),
            );
        }

        fn put_tail(&mut self, list_number: i64, tail_id: i64) {
            self.put(
                piece_coords_tail_key(list_number),
                tail_id.to_be_bytes().to_vec(),
            );
        }
    }

    impl OpReader for StubReader {
        fn read(&mut self, op: ReadOp) -> Result<crate::ProvenRead, ChangelogError> {
            self.reads.push(op.clone());
            match op {
                ReadOp::Key(key) => {
                    if let Some(results) = self.key_overrides.get(&key) {
                        return Ok(crate::ProvenRead {
                            op: ReadOp::Key(key),
                            results: results.clone(),
                        });
                    }
                    let results = self
                        .kv
                        .get(&key)
                        .map(|v| vec![(key.clone(), v.clone())])
                        .unwrap_or_default();
                    Ok(crate::ProvenRead {
                        op: ReadOp::Key(key),
                        results,
                    })
                }
                ReadOp::Range { start, end } => {
                    if let Some(results) = self.range_overrides.get(&start) {
                        return Ok(crate::ProvenRead {
                            op: ReadOp::Range { start, end },
                            results: results.clone(),
                        });
                    }
                    let results = self
                        .kv
                        .range(start.clone()..end.clone())
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    Ok(crate::ProvenRead {
                        op: ReadOp::Range { start, end },
                        results,
                    })
                }
                ReadOp::Prefix(prefix) => {
                    let end = prefix_successor(&prefix);
                    let results: Vec<_> = match end {
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
                    };
                    Ok(crate::ProvenRead {
                        op: ReadOp::Prefix(prefix),
                        results,
                    })
                }
            }
        }
    }

    fn stored_i64(value: i64) -> Vec<u8> {
        value_to_bytes(&json!(value)).unwrap()
    }

    fn piece_coord(buffer_id: i64, start_byte: u32, len_bytes: u32, tombstone: bool) -> PieceCoord {
        PieceCoord {
            buffer_id,
            start_byte,
            len_bytes,
            tombstone,
        }
    }

    fn row(id: i64, list_number: i64, prev_id: i64, next_id: i64, coord: PieceCoord) -> PieceRow {
        PieceRow {
            id,
            list_number,
            prev_id,
            next_id,
            coord,
        }
    }

    struct LcgRng(u64);

    impl LcgRng {
        fn new(seed: u64) -> Self {
            LcgRng(seed)
        }

        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 32) as u32
        }
    }

    #[test]
    fn resolve_coord_document_start_reads_head_key() {
        let mut reader = StubReader::default();
        reader.put_head(9, 42);

        let resolved = resolve_coord(
            &mut reader,
            9,
            BufferCoord::DOCUMENT_START,
            ResolvePurpose::InsertAnchor,
        )
        .unwrap();

        assert_eq!(
            resolved,
            IndexedResolveResult::DocumentStart { head_id: 42 }
        );
        assert_eq!(reader.reads, vec![ReadOp::Key(piece_coords_head_key(9))]);
    }

    #[test]
    fn resolve_coord_uses_buffer_id_index_and_predecessor_boundary_wins() {
        let mut reader = StubReader::default();
        let left = row(1, 9, 0, 2, piece_coord(5, 0, 20, false));
        let right = row(2, 9, 1, 0, piece_coord(5, 20, 20, false));
        reader.put_row(left.clone());
        reader.put_row(right);
        reader.put_buffer_index(5, 1);
        reader.put_buffer_index(5, 2);

        let resolved = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 20,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap();

        assert_eq!(
            resolved,
            IndexedResolveResult::InRow {
                row: left,
                offset: 20
            }
        );
        assert!(matches!(
            &reader.reads[0],
            ReadOp::Range { start, .. }
                if start == &index_value_prefix(
                    PIECE_COORDS_TABLE,
                    PIECE_COORDS_COL_BUFFER_ID,
                    5i64,
                )
                .unwrap()
        ));
    }

    #[test]
    fn resolve_coord_rejects_overlapping_same_buffer_rows() {
        let mut reader = StubReader::default();
        let first = row(1, 9, 0, 2, piece_coord(5, 0, 20, false));
        let second = row(2, 9, 1, 0, piece_coord(5, 8, 20, false));
        for piece in [first, second] {
            reader.put_row(piece.clone());
            reader.put_buffer_index(5, piece.id);
        }

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 12,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("coord contradiction"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_coord_tombstone_clamps_by_purpose() {
        let mut reader = StubReader::default();
        let live_left = row(1, 9, 0, 2, piece_coord(5, 0, 8, false));
        let tomb_a = row(2, 9, 1, 3, piece_coord(5, 8, 4, true));
        let tomb_b = row(3, 9, 2, 4, piece_coord(5, 12, 4, true));
        let live_right = row(4, 9, 3, 0, piece_coord(5, 16, 8, false));
        for piece in [
            live_left.clone(),
            tomb_a,
            tomb_b.clone(),
            live_right.clone(),
        ] {
            reader.put_row(piece.clone());
            reader.put_buffer_index(5, piece.id);
        }

        let coord = BufferCoord {
            buffer_id: 5,
            byte_pos: 12,
        };
        let insert_anchor =
            resolve_coord(&mut reader, 9, coord, ResolvePurpose::InsertAnchor).unwrap();
        assert_eq!(
            insert_anchor,
            IndexedResolveResult::ClampedToRow {
                row: live_left.clone(),
                direction: ClampDirection::Backward,
                hops: 1,
            }
        );

        let delete_end = resolve_coord(&mut reader, 9, coord, ResolvePurpose::DeleteEnd).unwrap();
        assert_eq!(
            delete_end,
            IndexedResolveResult::ClampedToRow {
                row: live_left,
                direction: ClampDirection::Backward,
                hops: 1,
            }
        );

        let delete_start =
            resolve_coord(&mut reader, 9, coord, ResolvePurpose::DeleteStart).unwrap();
        assert_eq!(
            delete_start,
            IndexedResolveResult::ClampedToRow {
                row: live_right,
                direction: ClampDirection::Forward,
                hops: 2,
            }
        );
    }

    #[test]
    fn resolve_coord_random_tombstone_runs_clamp_all_purposes() {
        let mut rng = LcgRng::new(0xB0FF_EE12_3456_7890);

        for _case in 0..64 {
            let list_number = 9;
            let buffer_id = 5 + i64::from(rng.next() % 17);
            let run_len = 1 + (rng.next() as usize % 8);
            let target_index = rng.next() as usize % run_len;

            let mut pieces = Vec::new();
            let mut start_byte = 0u32;

            // ×4 so every range lands on a UTF-32 scalar boundary; the
            // clamp geometry is unchanged.
            let left_len = (1 + (rng.next() % 5)) * 4;
            pieces.push(row(
                1,
                list_number,
                0,
                2,
                piece_coord(buffer_id, start_byte, left_len, false),
            ));
            start_byte += left_len;

            let mut coord = BufferCoord {
                buffer_id,
                byte_pos: 0,
            };
            for i in 0..run_len {
                let id = 2 + i as i64;
                let len_bytes = (2 + (rng.next() % 5)) * 4;
                if i == target_index {
                    // +4 (not +1): interior of the target tombstone piece
                    // (len_bytes >= 8) while staying on a UTF-32 scalar
                    // boundary; clamp geometry/hops are unchanged.
                    coord.byte_pos = start_byte + 4;
                }
                pieces.push(row(
                    id,
                    list_number,
                    id - 1,
                    id + 1,
                    piece_coord(buffer_id, start_byte, len_bytes, true),
                ));
                start_byte += len_bytes;
            }

            let right_id = 2 + run_len as i64;
            let right_len = (1 + (rng.next() % 5)) * 4;
            pieces.push(row(
                right_id,
                list_number,
                right_id - 1,
                0,
                piece_coord(buffer_id, start_byte, right_len, false),
            ));

            let live_left = pieces[0].clone();
            let live_right = pieces[run_len + 1].clone();
            let backward_hops = (target_index + 1) as u32;
            let forward_hops = (run_len - target_index) as u32;

            for (purpose, expected_row, expected_direction, expected_hops) in [
                (
                    ResolvePurpose::InsertAnchor,
                    live_left.clone(),
                    ClampDirection::Backward,
                    backward_hops,
                ),
                (
                    ResolvePurpose::DeleteEnd,
                    live_left.clone(),
                    ClampDirection::Backward,
                    backward_hops,
                ),
                (
                    ResolvePurpose::DeleteStart,
                    live_right.clone(),
                    ClampDirection::Forward,
                    forward_hops,
                ),
            ] {
                let mut reader = StubReader::default();
                for piece in &pieces {
                    reader.put_row(piece.clone());
                    reader.put_buffer_index(buffer_id, piece.id);
                }

                let resolved = resolve_coord(&mut reader, list_number, coord, purpose).unwrap();
                assert_eq!(
                    resolved,
                    IndexedResolveResult::ClampedToRow {
                        row: expected_row,
                        direction: expected_direction,
                        hops: expected_hops,
                    }
                );
            }
        }
    }

    #[test]
    fn resolve_coord_endpoint_clamps_read_head_and_tail_keys() {
        let mut backward = StubReader::default();
        let tomb_head = row(1, 9, 0, 2, piece_coord(5, 0, 4, true));
        backward.put_row(tomb_head);
        backward.put_buffer_index(5, 1);
        backward.put_head(9, 1);
        let resolved = resolve_coord(
            &mut backward,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 0,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap();
        assert_eq!(
            resolved,
            IndexedResolveResult::ClampedBeforeHead {
                head_id: 1,
                start_row_id: 1,
                hops: 1,
            }
        );
        assert!(backward
            .reads
            .iter()
            .any(|op| op == &ReadOp::Key(piece_coords_head_key(9))));

        let mut forward = StubReader::default();
        let tomb_tail = row(8, 9, 7, 0, piece_coord(5, 12, 8, true));
        forward.put_row(tomb_tail);
        forward.put_buffer_index(5, 8);
        forward.put_tail(9, 8);
        let resolved = resolve_coord(
            &mut forward,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 16,
            },
            ResolvePurpose::DeleteStart,
        )
        .unwrap();
        assert_eq!(
            resolved,
            IndexedResolveResult::ClampedAfterTail {
                tail_id: 8,
                start_row_id: 8,
                hops: 1,
            }
        );
        assert!(forward
            .reads
            .iter()
            .any(|op| op == &ReadOp::Key(piece_coords_tail_key(9))));
    }

    #[test]
    fn resolve_coord_rejects_wrong_key_returned_by_point_read() {
        let mut reader = StubReader::default();
        let piece = row(1, 9, 0, 0, piece_coord(5, 0, 5, false));
        reader.put_row(piece.clone());
        reader.put_buffer_index(5, 1);
        let requested = column_key(PIECE_COORDS_TABLE, 1, PIECE_COORDS_COL_LIST_NUMBER);
        let wrong = column_key(PIECE_COORDS_TABLE, 2, PIECE_COORDS_COL_LIST_NUMBER);
        reader
            .key_overrides
            .insert(requested, vec![(wrong, stored_i64(9))]);

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(err.to_string().contains("wrong key"));
    }

    #[test]
    fn resolve_coord_rejects_wrong_index_column_value() {
        let mut reader = StubReader::default();
        let prefix =
            index_value_prefix(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 5i64).unwrap();
        let wrong_key = index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, 6i64, 1).unwrap();
        reader
            .range_overrides
            .insert(prefix, vec![(wrong_key, row_id_to_bytes(1).to_vec())]);

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected 5"));
    }

    #[test]
    fn resolve_coord_rejects_missing_index_entry() {
        let mut reader = StubReader::default();
        reader.put_row(row(1, 9, 0, 0, piece_coord(5, 0, 5, false)));

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown piece-text coordinate"));
    }

    #[test]
    fn resolve_coord_rejects_unaligned_byte_pos() {
        // The public resolver must reject a caller coord that is not on a
        // UTF-32 scalar boundary, before any reads — closing the
        // byte-coordinate hazard for callers outside the envelope-validated
        // edit path.
        let mut reader = StubReader::default();
        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 1,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a multiple of 4"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_coord_rejects_row_from_other_document() {
        // The buffer_id index entry exists, but the resolved _piecetext_pieces
        // row lives in a different document (list_number). A BufferCoord only
        // names buffer_id/byte_pos, so the resolver must bind the row to the
        // caller's list instead of resolving a cross-document buffer.
        let mut reader = StubReader::default();
        let foreign = row(1, 7, 0, 0, piece_coord(5, 0, 20, false));
        reader.put_row(foreign);
        reader.put_buffer_index(5, 1);

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 8,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("requested list 9"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn clamp_walk_rejects_neighbour_from_other_document() {
        // The start tombstone is in list 9 and is the only indexed row, but
        // its prev pointer references a row in another document. The clamp
        // walk must reject the cross-document neighbour, not walk into it.
        let mut reader = StubReader::default();
        let tomb = row(2, 9, 1, 0, piece_coord(5, 0, 8, true));
        // Reachable only via the tombstone's prev pointer (not indexed under
        // buffer 5). next_id=2 keeps pointer symmetry valid so the list-number
        // binding is what rejects the walk.
        let foreign_prev = row(1, 7, 0, 2, piece_coord(6, 0, 8, false));
        reader.put_row(tomb);
        reader.put_row(foreign_prev);
        reader.put_buffer_index(5, 2);

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("clamp walk for list 9"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn clamp_backward_rejects_zero_prev_that_is_not_head() {
        // A tombstone reached via the buffer_id index has prev_id 0 (claiming to
        // be the chain head) but the head key names a different row. The indexed
        // path never authenticates the whole linked list, so it must bind the
        // endpoint claim to the head key and reject — instead of mis-clamping to
        // document start the way it would if it trusted the pointer. The
        // full-snapshot planner caught this via whole-list validation.
        let mut reader = StubReader::default();
        let tomb = row(2, 9, 0, 0, piece_coord(5, 0, 8, true));
        reader.put_row(tomb);
        reader.put_buffer_index(5, 2);
        reader.put_head(9, 1); // head is row 1, not the matched row 2

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("is not the document head"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn clamp_forward_rejects_zero_next_that_is_not_tail() {
        // Mirror of the backward case: a tombstone with next_id 0 that is not the
        // tail must be rejected on a forward (DeleteStart) clamp rather than
        // mis-clamping past document end.
        let mut reader = StubReader::default();
        let tomb = row(2, 9, 0, 0, piece_coord(5, 0, 8, true));
        reader.put_row(tomb);
        reader.put_buffer_index(5, 2);
        reader.put_tail(9, 9); // tail is row 9, not the matched row 2

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 4,
            },
            ResolvePurpose::DeleteStart,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("is not the document tail"),
            "unexpected error: {err}"
        );
    }

    // resolve_coord_rejects_row_buffer_id_mismatch deleted — index
    // put's column-value matches the row's column value by spec-check on
    // every accepted op. Inductively guaranteed.

    #[test]
    fn resolve_coord_rejects_contradicting_tombstone_clamp_walk() {
        // Clamp-walk pointer symmetry is a hard invariant. It used to be a
        // dev-build debug_assert! canary, but debug assertions vanish in
        // release / zkVM builds, so a corrupted prev/next pointer must be a
        // hard error the verifier can rely on.
        let mut reader = StubReader::default();
        let live_left = row(1, 9, 0, 99, piece_coord(5, 0, 8, false));
        let tomb = row(2, 9, 1, 0, piece_coord(5, 8, 8, true));
        for piece in [live_left, tomb] {
            reader.put_row(piece.clone());
            reader.put_buffer_index(5, piece.id);
        }

        let err = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 5,
                byte_pos: 12,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tombstone clamp contradiction"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_coord_random_valid_chains_find_unique_covering_piece() {
        let mut reader = StubReader::default();
        let mut starts_by_buffer = BTreeMap::<i64, u32>::new();
        let mut pieces = Vec::new();
        for id in 1..=50 {
            let buffer_id = (id % 7) + 1;
            let start = starts_by_buffer.entry(buffer_id).or_insert(0);
            let piece = row(
                id,
                9,
                if id == 1 { 0 } else { id - 1 },
                if id == 50 { 0 } else { id + 1 },
                piece_coord(buffer_id, *start, 40, false),
            );
            *start += 40;
            reader.put_row(piece.clone());
            reader.put_buffer_index(buffer_id, id);
            pieces.push(piece);
        }

        for i in [0usize, 3, 8, 17, 29, 41, 49] {
            let piece = pieces[i].clone();
            let resolved = resolve_coord(
                &mut reader,
                9,
                BufferCoord {
                    buffer_id: piece.coord.buffer_id,
                    byte_pos: piece.coord.start_byte + 20,
                },
                ResolvePurpose::InsertAnchor,
            )
            .unwrap();
            assert_eq!(
                resolved,
                IndexedResolveResult::InRow {
                    row: piece,
                    offset: 20,
                }
            );
        }
    }

    #[test]
    fn resolve_coord_read_count_scales_with_buffer_fanout_not_document_size() {
        let mut reader = StubReader::default();
        for id in 1..=1000 {
            let piece = row(
                id,
                9,
                if id == 1 { 0 } else { id - 1 },
                if id == 1000 { 0 } else { id + 1 },
                piece_coord(id, 0, 40, false),
            );
            reader.put_row(piece.clone());
            reader.put_buffer_index(id, id);
        }

        let resolved = resolve_coord(
            &mut reader,
            9,
            BufferCoord {
                buffer_id: 1000,
                byte_pos: 20,
            },
            ResolvePurpose::InsertAnchor,
        )
        .unwrap();
        assert!(matches!(
            resolved,
            IndexedResolveResult::InRow {
                row: PieceRow { id: 1000, .. },
                offset: 20
            }
        ));
        assert_eq!(reader.reads.len(), 8);
    }

    #[test]
    fn piece_coords_index_helper_matches_standard_insert_index_puts() {
        let helper = piece_coords_insert_index_puts(7, 3, 5).unwrap();
        let expected = vec![
            make_index_put(
                PIECE_COORDS_TABLE,
                PIECE_COORDS_COL_BUFFER_ID,
                &value_to_bytes(&json!(5)).unwrap(),
                7,
                "test",
            )
            .unwrap(),
            make_index_put(
                PIECE_COORDS_TABLE,
                PIECE_COORDS_COL_LIST_NUMBER,
                &value_to_bytes(&json!(3)).unwrap(),
                7,
                "test",
            )
            .unwrap(),
        ];
        assert_eq!(helper, expected);
    }

    #[test]
    fn buffers_index_helper_matches_standard_insert_index_puts() {
        let helper = buffers_insert_index_puts(11, "channels", 42, "notes_pieces").unwrap();
        let expected = vec![
            make_index_put(
                BUFFERS_TABLE,
                BUFFERS_COL_OWNER_COLUMN,
                &value_to_bytes(&json!("notes_pieces")).unwrap(),
                11,
                "test",
            )
            .unwrap(),
            make_index_put(
                BUFFERS_TABLE,
                BUFFERS_COL_OWNER_ROW_ID,
                &value_to_bytes(&json!(42)).unwrap(),
                11,
                "test",
            )
            .unwrap(),
            make_index_put(
                BUFFERS_TABLE,
                BUFFERS_COL_OWNER_TABLE,
                &value_to_bytes(&json!("channels")).unwrap(),
                11,
                "test",
            )
            .unwrap(),
        ];
        assert_eq!(helper, expected);
    }
}
