//! Structural-integrity scan for a single PieceText document.
//!
//! [`SpaceState::assert_piece_text_invariants`](super::SpaceState::assert_piece_text_invariants)
//! re-derives the `_piecetext_pieces` linked list and its `_piecetext_buffers` from authenticated
//! tree state and checks that the document is internally consistent: the parent
//! cell resolves to a list, head/tail are coherent, the chain is acyclic and
//! fully connected with correct `prev`/`next` pointers, every piece references a
//! present buffer, and piece byte ranges stay within their buffer and do not
//! overlap.
//!
//! This is a read-only admin/test helper. The signed `PieceTextEdit` verifier
//! ([`PieceTextEditOp`](encrypted_spaces_changelog_core::ops::PieceTextEditOp)) is
//! what enforces these properties at edit time; this scan runs as a
//! `debug_assertions` self-check after each applied edit and is exercised
//! directly by tests. It contains no cleanup logic.

use std::collections::{BTreeMap, BTreeSet};

use encrypted_spaces_backend::internal_schemas::{BUFFERS_TABLE_NAME, PIECE_COORDS_TABLE_NAME};
use encrypted_spaces_backend::merk_storage::{parse_key, stored_value, ParsedKey};
use encrypted_spaces_changelog_core::piece_text::PieceTextAddress;
use encrypted_spaces_storage_encoding::{keys, TupleElement};
use serde_json::Value;

use super::{ServerError, SpaceState};

/// Summary returned by a successful integrity scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceTextInvariantReport {
    pub list_number: i64,
    pub piece_count: usize,
    pub live_piece_count: usize,
    pub tombstone_piece_count: usize,
    pub buffer_count: usize,
}

#[derive(Debug, Clone)]
struct InvariantPieceRow {
    id: i64,
    prev_id: i64,
    next_id: i64,
    buffer_id: i64,
    start_byte: u32,
    len_bytes: u32,
    tombstone: bool,
}

#[derive(Debug, Clone)]
struct InvariantBufferRow {
    id: i64,
    len_bytes: u32,
}

fn json_i64_field(row: &Value, field: &str, label: &str) -> Result<i64, ServerError> {
    row.get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| ServerError::Generic(format!("{label} missing or not an integer: {field}")))
}

fn json_string_field(row: &Value, field: &str, label: &str) -> Result<String, ServerError> {
    row.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ServerError::Generic(format!("{label} missing or not a string: {field}")))
}

fn json_u32_field(row: &Value, field: &str, label: &str) -> Result<u32, ServerError> {
    let value = json_i64_field(row, field, label)?;
    u32::try_from(value).map_err(|_| {
        ServerError::Generic(format!(
            "{label} field {field} value {value} is outside u32 range"
        ))
    })
}

fn parse_piece_row_for_invariants(
    row: &Value,
    list_number: i64,
) -> Result<InvariantPieceRow, ServerError> {
    let id = json_i64_field(row, "id", "_piecetext_pieces row")?;
    if id <= 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: piece row has non-positive id {id}"
        )));
    }
    let row_list_number = json_i64_field(row, "list_number", "_piecetext_pieces row")?;
    if row_list_number != list_number {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: piece row {id} has list_number {row_list_number}, expected {list_number}"
        )));
    }
    let prev_id = json_i64_field(row, "prev_id", "_piecetext_pieces row")?;
    let next_id = json_i64_field(row, "next_id", "_piecetext_pieces row")?;
    if prev_id < 0 || next_id < 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: piece row {id} has negative pointer prev_id={prev_id} next_id={next_id}"
        )));
    }
    let buffer_id = json_i64_field(row, "buffer_id", "_piecetext_pieces row")?;
    if buffer_id <= 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: piece row {id} has non-positive buffer_id {buffer_id}"
        )));
    }
    let start_byte = json_u32_field(row, "start_byte", "_piecetext_pieces row")?;
    let len_bytes = json_u32_field(row, "len_bytes", "_piecetext_pieces row")?;
    if len_bytes == 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: piece row {id} has zero len_bytes"
        )));
    }
    let tombstone_raw = json_i64_field(row, "tombstone", "_piecetext_pieces row")?;
    let tombstone = match tombstone_raw {
        0 => false,
        1 => true,
        other => {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: piece row {id} has invalid tombstone {other}"
            )))
        }
    };
    start_byte.checked_add(len_bytes).ok_or_else(|| {
        ServerError::Generic(format!(
            "piece-text invariant violation: piece row {id} byte range overflows"
        ))
    })?;

    Ok(InvariantPieceRow {
        id,
        prev_id,
        next_id,
        buffer_id,
        start_byte,
        len_bytes,
        tombstone,
    })
}

fn parse_buffer_row_for_invariants(
    row: &Value,
    address: &PieceTextAddress,
) -> Result<InvariantBufferRow, ServerError> {
    let id = json_i64_field(row, "id", "_piecetext_buffers row")?;
    if id <= 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: buffer row has non-positive id {id}"
        )));
    }
    let owner_table = json_string_field(row, "owner_table", "_piecetext_buffers row")?;
    let owner_row_id = json_i64_field(row, "owner_row_id", "_piecetext_buffers row")?;
    let owner_column = json_string_field(row, "owner_column", "_piecetext_buffers row")?;
    if owner_table != address.table
        || owner_row_id != address.row_id
        || owner_column != address.column
    {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: buffer {id} owner mismatch: \
             stored=({owner_table}, {owner_row_id}, {owner_column}), expected=({}, {}, {})",
            address.table, address.row_id, address.column
        )));
    }
    let author_id = json_i64_field(row, "author_id", "_piecetext_buffers row")?;
    if author_id < 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: buffer {id} has negative author_id {author_id}"
        )));
    }
    let len_bytes = json_u32_field(row, "len_bytes", "_piecetext_buffers row")?;
    if len_bytes == 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: buffer {id} has zero len_bytes"
        )));
    }
    Ok(InvariantBufferRow { id, len_bytes })
}

fn validate_piece_chain_for_invariants(
    pieces: &[InvariantPieceRow],
    head_id: i64,
    tail_id: i64,
) -> Result<Vec<InvariantPieceRow>, ServerError> {
    if (head_id == 0) != (tail_id == 0) {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: head_id={head_id} and tail_id={tail_id} must both be zero or both be non-zero"
        )));
    }
    if pieces.is_empty() {
        if head_id != 0 || tail_id != 0 {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: empty piece list has head_id={head_id} tail_id={tail_id}"
            )));
        }
        return Ok(Vec::new());
    }
    if head_id <= 0 || tail_id <= 0 {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: non-empty piece list has head_id={head_id} tail_id={tail_id}"
        )));
    }

    let mut by_id = BTreeMap::new();
    for piece in pieces {
        if by_id.insert(piece.id, piece.clone()).is_some() {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: duplicate piece row id {}",
                piece.id
            )));
        }
    }

    let mut ordered = Vec::with_capacity(pieces.len());
    let mut current_id = head_id;
    let mut expected_prev = 0i64;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current_id) {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: cycle detected at piece row {current_id}"
            )));
        }
        let piece = by_id.get(&current_id).ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: chain references missing piece row {current_id}"
            ))
        })?;
        if piece.prev_id != expected_prev {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: piece row {} prev_id={} expected {}",
                piece.id, piece.prev_id, expected_prev
            )));
        }
        ordered.push(piece.clone());
        if piece.next_id == 0 {
            if piece.id != tail_id {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: row {} has next_id=0 but tail_id={tail_id}",
                    piece.id
                )));
            }
            break;
        }
        expected_prev = piece.id;
        current_id = piece.next_id;
        if ordered.len() > pieces.len() {
            return Err(ServerError::Generic(
                "piece-text invariant violation: chain walk exceeded fetched row count".to_string(),
            ));
        }
    }

    if ordered.len() != pieces.len() {
        return Err(ServerError::Generic(format!(
            "piece-text invariant violation: walked {} piece rows but fetched {}; orphaned rows exist",
            ordered.len(),
            pieces.len()
        )));
    }
    Ok(ordered)
}

impl SpaceState {
    /// Admin/test-only integrity scan for one piece-text document.
    pub fn assert_piece_text_invariants(
        &self,
        address: &PieceTextAddress,
    ) -> Result<PieceTextInvariantReport, ServerError> {
        address.validate().map_err(|e| {
            ServerError::Generic(format!("Invalid PieceTextAddress for invariant check: {e}"))
        })?;

        let list_number = self.read_piece_text_list_number_for_invariants(address)?;
        self.check_piece_text_parent_key_for_invariants(address, list_number)?;
        let head_id = self.read_piece_text_endpoint_for_invariants("head", list_number)?;
        let tail_id = self.read_piece_text_endpoint_for_invariants("tail", list_number)?;

        let pieces = self.read_piece_rows_for_invariants(list_number)?;
        let ordered = validate_piece_chain_for_invariants(&pieces, head_id, tail_id)?;
        let buffers = self.read_buffer_rows_for_invariants(address, &ordered)?;

        let mut ranges_by_buffer: BTreeMap<i64, Vec<(u32, u32)>> = BTreeMap::new();
        let mut live_piece_count = 0usize;
        let mut tombstone_piece_count = 0usize;
        for piece in &ordered {
            if piece.tombstone {
                tombstone_piece_count += 1;
            } else {
                live_piece_count += 1;
            }
            let buffer = buffers.get(&piece.buffer_id).ok_or_else(|| {
                ServerError::Generic(format!(
                    "piece-text invariant violation: piece row {} references missing buffer {}",
                    piece.id, piece.buffer_id
                ))
            })?;
            let end = piece
                .start_byte
                .checked_add(piece.len_bytes)
                .ok_or_else(|| {
                    ServerError::Generic(format!(
                        "piece-text invariant violation: piece row {} byte range overflows",
                        piece.id
                    ))
                })?;
            if end > buffer.len_bytes {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: piece row {} range [{}..{}) exceeds \
                     buffer {} len_bytes {}",
                    piece.id, piece.start_byte, end, piece.buffer_id, buffer.len_bytes
                )));
            }
            ranges_by_buffer
                .entry(piece.buffer_id)
                .or_default()
                .push((piece.start_byte, end));
        }

        for (buffer_id, ranges) in &mut ranges_by_buffer {
            ranges.sort_by_key(|&(start, _)| start);
            for window in ranges.windows(2) {
                let (_, prev_end) = window[0];
                let (next_start, _) = window[1];
                if next_start < prev_end {
                    return Err(ServerError::Generic(format!(
                        "piece-text invariant violation: buffer {buffer_id} has overlapping \
                         piece ranges (prev_end={prev_end}, next_start={next_start})"
                    )));
                }
            }
        }

        Ok(PieceTextInvariantReport {
            list_number,
            piece_count: ordered.len(),
            live_piece_count,
            tombstone_piece_count,
            buffer_count: buffers.len(),
        })
    }

    fn read_piece_text_list_number_for_invariants(
        &self,
        address: &PieceTextAddress,
    ) -> Result<i64, ServerError> {
        let key = keys::column_key(&address.table, address.row_id, &address.column);
        let bytes = self.db.get_value(&key).map_err(|e| {
            ServerError::Generic(format!(
                "piece-text invariant check failed to read parent PieceText cell: {e}"
            ))
        })?;
        let bytes = bytes.ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: parent PieceText cell {}.{}.{} is absent",
                address.table, address.row_id, address.column
            ))
        })?;
        let value = stored_value::bytes_to_value(&bytes).map_err(|e| {
            ServerError::Generic(format!(
                "piece-text invariant violation: failed to decode parent PieceText cell \
                 {}.{}.{}: {e}",
                address.table, address.row_id, address.column
            ))
        })?;
        let list_number = value.as_i64().ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: parent PieceText cell {}.{}.{} is not an integer",
                address.table, address.row_id, address.column
            ))
        })?;
        if list_number <= 0 {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: parent PieceText cell has invalid list_number {list_number}"
            )));
        }
        Ok(list_number)
    }

    fn check_piece_text_parent_key_for_invariants(
        &self,
        address: &PieceTextAddress,
        list_number: i64,
    ) -> Result<(), ServerError> {
        let key = keys::piece_coords_parent_key(list_number);
        let bytes = self.db.get_value(&key)?.ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: piece_coords_parent_key({list_number}) is absent"
            ))
        })?;
        let (table, row_id, column) = keys::decode_list_parent(&bytes).map_err(|e| {
            ServerError::Generic(format!(
                "piece-text invariant violation: piece_coords_parent_key({list_number}) \
                 failed to decode: {e}"
            ))
        })?;
        if table != address.table || row_id != address.row_id || column != address.column {
            return Err(ServerError::Generic(format!(
                "piece-text invariant violation: piece_coords_parent_key({list_number}) \
                 resolves to ({table}, {row_id}, {column}), expected ({}, {}, {})",
                address.table, address.row_id, address.column
            )));
        }
        Ok(())
    }

    fn read_piece_text_endpoint_for_invariants(
        &self,
        endpoint: &str,
        list_number: i64,
    ) -> Result<i64, ServerError> {
        let key = match endpoint {
            "head" => keys::piece_coords_head_key(list_number),
            "tail" => keys::piece_coords_tail_key(list_number),
            other => {
                return Err(ServerError::Generic(format!(
                    "unknown piece-text endpoint '{other}'"
                )))
            }
        };
        let bytes = self.db.get_value(&key)?.ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: piece_coords_{endpoint}_key({list_number}) is absent"
            ))
        })?;
        let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
            ServerError::Generic(format!(
                "piece-text invariant violation: piece_coords_{endpoint}_key({list_number}) \
                 has {} bytes, expected 8",
                bytes.len()
            ))
        })?;
        Ok(i64::from_be_bytes(arr))
    }

    fn read_piece_rows_for_invariants(
        &self,
        list_number: i64,
    ) -> Result<Vec<InvariantPieceRow>, ServerError> {
        let row_ids = self.read_piece_row_ids_for_list_for_invariants(list_number)?;
        let mut pieces = Vec::new();
        for row_id in row_ids {
            let mut row = serde_json::Map::new();
            row.insert("id".to_string(), Value::Number(row_id.into()));
            for column in [
                "list_number",
                "prev_id",
                "next_id",
                "buffer_id",
                "start_byte",
                "len_bytes",
                "tombstone",
            ] {
                row.insert(
                    column.to_string(),
                    self.read_json_column_for_invariants(PIECE_COORDS_TABLE_NAME, row_id, column)?,
                );
            }
            pieces.push(parse_piece_row_for_invariants(
                &Value::Object(row),
                list_number,
            )?);
        }
        pieces.sort_by_key(|row| row.id);
        Ok(pieces)
    }

    fn read_piece_row_ids_for_list_for_invariants(
        &self,
        list_number: i64,
    ) -> Result<Vec<i64>, ServerError> {
        let prefix = keys::index_value_prefix(PIECE_COORDS_TABLE_NAME, "list_number", list_number)
            .map_err(|e| {
                ServerError::Generic(format!(
                    "failed to build _piecetext_pieces list_number index prefix: {e}"
                ))
            })?;
        let entries = self.db.iter_prefix_entries(&prefix).map_err(|e| {
            ServerError::Generic(format!(
                "failed to scan _piecetext_pieces list_number={list_number} index: {e}"
            ))
        })?;
        let mut row_ids = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let parsed = parse_key(&key).map_err(|e| {
                ServerError::Generic(format!(
                    "piece-text invariant violation: failed to parse list_number index key: {e}"
                ))
            })?;
            let ParsedKey::Index {
                table,
                column,
                value: index_value,
                row_id,
            } = parsed
            else {
                return Err(ServerError::Generic(
                    "piece-text invariant violation: list_number prefix returned non-index key"
                        .to_string(),
                ));
            };
            if table != PIECE_COORDS_TABLE_NAME || column != "list_number" {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: list_number prefix returned index for {table}.{column}"
                )));
            }
            if index_value != TupleElement::Int(list_number) {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: list_number index returned value {index_value:?}, expected {list_number}"
                )));
            }
            if row_id <= 0 {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: list_number index returned non-positive row id {row_id}"
                )));
            }
            if value.as_slice() != keys::row_id_to_bytes(row_id) {
                return Err(ServerError::Generic(format!(
                    "piece-text invariant violation: list_number index entry for row {row_id} has wrong value"
                )));
            }
            row_ids.push(row_id);
        }
        row_ids.sort_unstable();
        Ok(row_ids)
    }

    fn read_json_column_for_invariants(
        &self,
        table: &str,
        row_id: i64,
        column: &str,
    ) -> Result<Value, ServerError> {
        let key = keys::column_key(table, row_id, column);
        let bytes = self.db.get_value(&key)?.ok_or_else(|| {
            ServerError::Generic(format!(
                "piece-text invariant violation: {table}.{row_id}.{column} is absent"
            ))
        })?;
        stored_value::bytes_to_value(&bytes).map_err(|e| {
            ServerError::Generic(format!(
                "piece-text invariant violation: failed to decode {table}.{row_id}.{column}: {e}"
            ))
        })
    }

    fn read_buffer_rows_for_invariants(
        &self,
        address: &PieceTextAddress,
        pieces: &[InvariantPieceRow],
    ) -> Result<BTreeMap<i64, InvariantBufferRow>, ServerError> {
        let buffer_ids: BTreeSet<i64> = pieces.iter().map(|piece| piece.buffer_id).collect();
        let mut buffers = BTreeMap::new();
        for id in buffer_ids {
            let mut row = serde_json::Map::new();
            row.insert("id".to_string(), Value::Number(id.into()));
            for column in [
                "owner_table",
                "owner_row_id",
                "owner_column",
                "author_id",
                "len_bytes",
            ] {
                row.insert(
                    column.to_string(),
                    self.read_json_column_for_invariants(BUFFERS_TABLE_NAME, id, column)?,
                );
            }
            let buffer = parse_buffer_row_for_invariants(&Value::Object(row), address)?;
            buffers.insert(buffer.id, buffer);
        }
        Ok(buffers)
    }
}
