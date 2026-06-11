use std::collections::BTreeSet;

use super::{
    decode_i64_column_value, read_schema_piece_text_columns, OpContext, OpReader, OpVerifier,
    OpVerifyResult,
};
use crate::changelog::{ChangelogEntry, ChangelogError};
use crate::piece_text::PieceTextAddress;
use crate::piece_text_cleanup::PieceTextCleanupBuffersEnvelopeV1;
use crate::piece_text_resolver::{
    buffers_delete_index_deletes, BUFFERS_COL_OWNER_COLUMN, BUFFERS_COL_OWNER_ROW_ID,
    BUFFERS_COL_OWNER_TABLE, PIECE_COORDS_COL_BUFFER_ID,
};
use crate::{prefix_successor, BatchOp, ReadOp, TraceStep};
use encrypted_spaces_storage_encoding::keys::{
    column_key, index_value_prefix, BUFFERS_TABLE, PIECE_COORDS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::bytes_to_value;

pub struct PieceTextCleanupBuffersOp;

const OP_NAME: &str = "piece_text_cleanup_buffers";
const BUFFERS_COL_AUTHOR_ID: &str = "author_id";
const BUFFERS_COL_LEN_BYTES: &str = "len_bytes";
const BUFFERS_COL_CONTENTS: &str = "contents";

const BUFFERS_COLUMNS: &[&str] = &[
    BUFFERS_COL_OWNER_TABLE,
    BUFFERS_COL_OWNER_ROW_ID,
    BUFFERS_COL_OWNER_COLUMN,
    BUFFERS_COL_AUTHOR_ID,
    BUFFERS_COL_LEN_BYTES,
    BUFFERS_COL_CONTENTS,
];

impl OpVerifier for PieceTextCleanupBuffersOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let envelope = PieceTextCleanupBuffersEnvelopeV1::decode_from_entry(entry)?;
        validate_current_change_id(envelope.op_id, ctx)?;

        let piece_text_columns =
            read_schema_piece_text_columns(&envelope.address.table, reader, ctx)?;
        if !piece_text_columns.contains(&envelope.address.column) {
            return Err(ChangelogError::Generic(format!(
                "{OP_NAME}: column '{}.{}' is not declared as PieceText",
                envelope.address.table, envelope.address.column
            )));
        }

        let mut batch_ops = Vec::new();
        let mut write_keys = BTreeSet::new();
        for &buffer_id in &envelope.buffer_removals {
            let owner = read_buffer_owner_meta(reader, buffer_id)?;
            validate_owner_matches(buffer_id, &owner, &envelope.address)?;
            require_empty_piece_coord_buffer_range(reader, buffer_id)?;
            materialise_buffer_delete_writes(buffer_id, &owner, &mut batch_ops, &mut write_keys)?;
        }

        Ok(OpVerifyResult {
            write_steps: vec![TraceStep::Write(batch_ops)],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BufferOwnerMeta {
    owner_table: String,
    owner_row_id: i64,
    owner_column: String,
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

fn read_buffer_owner_meta(
    reader: &mut dyn OpReader,
    buffer_id: i64,
) -> Result<BufferOwnerMeta, ChangelogError> {
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
    Ok(BufferOwnerMeta {
        owner_table,
        owner_row_id,
        owner_column,
    })
}

fn validate_owner_matches(
    buffer_id: i64,
    owner: &BufferOwnerMeta,
    address: &PieceTextAddress,
) -> Result<(), ChangelogError> {
    if owner.owner_table != address.table
        || owner.owner_row_id != address.row_id
        || owner.owner_column != address.column
    {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: buffer {buffer_id} owner address ({}, {}, {}) does not match envelope ({}, {}, {})",
            owner.owner_table,
            owner.owner_row_id,
            owner.owner_column,
            address.table,
            address.row_id,
            address.column
        )));
    }
    Ok(())
}

fn require_empty_piece_coord_buffer_range(
    reader: &mut dyn OpReader,
    buffer_id: i64,
) -> Result<(), ChangelogError> {
    let start = index_value_prefix(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, buffer_id)
        .map_err(|e| {
            ChangelogError::Generic(format!(
                "{OP_NAME}: failed to build buffer_id index prefix: {e}"
            ))
        })?;
    let end = prefix_successor(&start).ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{OP_NAME}: buffer_id index prefix has no successor"
        ))
    })?;
    let read = reader.read(ReadOp::Range {
        start: start.clone(),
        end,
    })?;
    if !read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: buffer {buffer_id} is still referenced by {} _piecetext_pieces.buffer_id index entr{}",
            read.results.len(),
            if read.results.len() == 1 { "y" } else { "ies" }
        )));
    }
    Ok(())
}

fn materialise_buffer_delete_writes(
    buffer_id: i64,
    owner: &BufferOwnerMeta,
    batch_ops: &mut Vec<BatchOp>,
    write_keys: &mut BTreeSet<Vec<u8>>,
) -> Result<(), ChangelogError> {
    for column in BUFFERS_COLUMNS {
        push_unique_op(
            batch_ops,
            write_keys,
            BatchOp::Delete {
                key: column_key(BUFFERS_TABLE, buffer_id, column),
            },
        )?;
    }
    for op in buffers_delete_index_deletes(
        buffer_id,
        &owner.owner_table,
        owner.owner_row_id,
        &owner.owner_column,
    )? {
        push_unique_op(batch_ops, write_keys, op)?;
    }
    Ok(())
}

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
    if read.results.len() != 1 {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {table} row {row_id} column '{column}' read returned {} results, expected 1",
            read.results.len()
        )));
    }
    let (returned_key, bytes) = &read.results[0];
    if returned_key != &key {
        return Err(ChangelogError::Generic(format!(
            "{OP_NAME}: {table} row {row_id} column '{column}' read returned wrong key"
        )));
    }
    Ok(bytes.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{ChangelogEntry, LogMessage, OpType, ROOT_TREE_PATH};
    use crate::ops::dispatch_extract_and_validate;
    use crate::piece_text_cleanup::PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1;
    use encrypted_spaces_storage_encoding::keys::{
        index_key, row_id_to_bytes, schema_piece_text_columns_key,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
    use std::collections::BTreeMap;

    const TABLE: &str = "docs";
    const ROW_ID: i64 = 42;
    const COLUMN: &str = "body";
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

        fn setup_base(&mut self) {
            let mut cols = BTreeSet::new();
            cols.insert(COLUMN.to_string());
            self.put(
                schema_piece_text_columns_key(TABLE),
                encrypted_spaces_storage_encoding::encode_column_names(&cols),
            );
        }

        fn put_buffer(&mut self, buffer_id: i64) {
            self.put_buffer_for(buffer_id, TABLE, ROW_ID, COLUMN);
        }

        fn put_buffer_for(
            &mut self,
            buffer_id: i64,
            owner_table: &str,
            owner_row_id: i64,
            owner_column: &str,
        ) {
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_TABLE),
                stored_string(owner_table),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_ROW_ID),
                stored_i64(owner_row_id),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_COLUMN),
                stored_string(owner_column),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_AUTHOR_ID),
                stored_i64(7),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_LEN_BYTES),
                stored_i64(4),
            );
            self.put(
                column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_CONTENTS),
                vec![0xAB; 32],
            );
            for op in
                buffers_delete_index_deletes(buffer_id, owner_table, owner_row_id, owner_column)
                    .unwrap()
            {
                let BatchOp::Delete { key } = op else {
                    panic!("expected index delete helper to return deletes");
                };
                self.put(key, row_id_to_bytes(buffer_id).to_vec());
            }
        }

        fn put_piece_buffer_ref(&mut self, buffer_id: i64, piece_row_id: i64) {
            self.put(
                index_key(
                    PIECE_COORDS_TABLE,
                    PIECE_COORDS_COL_BUFFER_ID,
                    buffer_id,
                    piece_row_id,
                )
                .unwrap(),
                row_id_to_bytes(piece_row_id).to_vec(),
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

    fn stored_string(value: &str) -> Vec<u8> {
        value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn address() -> PieceTextAddress {
        PieceTextAddress {
            table: TABLE.to_string(),
            row_id: ROW_ID,
            column: COLUMN.to_string(),
        }
    }

    fn envelope(buffer_removals: Vec<i64>) -> PieceTextCleanupBuffersEnvelopeV1 {
        PieceTextCleanupBuffersEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address: address(),
            op_id: OP_ID,
            buffer_removals,
        }
    }

    fn entry(env: &PieceTextCleanupBuffersEnvelopeV1) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 0,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::PieceTextCleanupBuffers,
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
        env: &PieceTextCleanupBuffersEnvelopeV1,
    ) -> Result<Vec<BatchOp>, ChangelogError> {
        let result = PieceTextCleanupBuffersOp::extract_and_validate(
            &entry(env),
            reader,
            &OpContext::for_change_id(OP_ID as usize),
        )?;
        let TraceStep::Write(ops) = &result.write_steps[0] else {
            panic!("expected write step");
        };
        Ok(ops.clone())
    }

    #[test]
    fn piece_text_cleanup_buffers_deletes_buffer_when_buffer_id_range_empty() {
        let env = envelope(vec![30, 40]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        reader.put_buffer(30);
        reader.put_buffer(40);

        let ops = verify(&mut reader, &env).unwrap();

        assert_eq!(ops.len(), 18);
        for buffer_id in [30, 40] {
            for column in BUFFERS_COLUMNS {
                assert!(ops.iter().any(|op| {
                    matches!(
                        op,
                        BatchOp::Delete { key }
                            if key == &column_key(BUFFERS_TABLE, buffer_id, column)
                    )
                }));
            }
            for expected in buffers_delete_index_deletes(buffer_id, TABLE, ROW_ID, COLUMN).unwrap()
            {
                assert!(ops.contains(&expected));
            }
        }
        assert!(reader.reads.iter().any(|read| {
            matches!(
                read,
                ReadOp::Range { start, .. }
                    if start == &index_value_prefix(
                        PIECE_COORDS_TABLE,
                        PIECE_COORDS_COL_BUFFER_ID,
                        30
                    )
                    .unwrap()
            )
        }));
    }

    #[test]
    fn piece_text_cleanup_buffers_rejects_when_any_index_ref_remains() {
        let env = envelope(vec![30]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        reader.put_buffer(30);
        reader.put_piece_buffer_ref(30, 900);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("still referenced"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_buffers_rejects_owner_address_mismatch() {
        let env = envelope(vec![30]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        reader.put_buffer_for(30, TABLE, ROW_ID + 1, COLUMN);

        let err = verify(&mut reader, &env).unwrap_err().to_string();

        assert!(err.contains("owner address"), "{err}");
    }

    #[test]
    fn piece_text_cleanup_buffers_dispatches_through_ops_mod() {
        let env = envelope(vec![30]);
        let mut reader = FakeReader::default();
        reader.setup_base();
        reader.put_buffer(30);

        let result = dispatch_extract_and_validate(
            &entry(&env),
            &mut reader,
            &OpContext::for_change_id(OP_ID as usize),
        )
        .unwrap();

        assert_eq!(result.write_steps.len(), 1);
    }
}
