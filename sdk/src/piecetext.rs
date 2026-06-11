//! Minimal SDK surface for `ColumnType::PieceText`.
//!
//! `PieceTextArea` is a handle to one PieceText document. Public writes are
//! scalar-indexed and compile into one signed `PieceTextEdit` changelog entry.

use crate::crypto::{current_encryption_key, decrypt_table_rows_strict};
use crate::Space;
use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::internal_schemas::{BUFFERS_TABLE_NAME, PIECE_COORDS_TABLE_NAME};
use encrypted_spaces_changelog_core::changelog::{Change, ChangelogEntry, HashedValues, OpType};
pub(crate) use encrypted_spaces_changelog_core::piece_text::PieceTextAddress;
use encrypted_spaces_changelog_core::piece_text::{
    BufferCoord, InsertedBufferManifest, PieceCoord, PieceTextEditEnvelopeV1,
    PieceTextEditItemManifest, PieceTextEditManifest, MAX_PIECETEXT_ENCRYPTED_BODY_BYTES,
    MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT, PIECE_TEXT_ENVELOPE_VERSION_V1,
    PIECE_TEXT_UTF32_BYTES_PER_SCALAR,
};
use encrypted_spaces_crypto::encryption::encrypt_field;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
struct RenderedPiece {
    id: i64,
    coord: PieceCoord,
}

#[derive(Clone, Debug)]
struct BufferData {
    contents: Vec<u8>,
}

const UTF32_BYTES_PER_SCALAR: usize = PIECE_TEXT_UTF32_BYTES_PER_SCALAR as usize;

fn encode_utf32le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.chars().count() * UTF32_BYTES_PER_SCALAR);
    for ch in text.chars() {
        out.extend_from_slice(&(ch as u32).to_le_bytes());
    }
    out
}

fn decode_utf32le_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / UTF32_BYTES_PER_SCALAR);
    let mut chunks = bytes.chunks_exact(UTF32_BYTES_PER_SCALAR);
    for chunk in &mut chunks {
        let unit = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        out.push(char::from_u32(unit).unwrap_or('\u{FFFD}'));
    }
    if !chunks.remainder().is_empty() {
        out.push('\u{FFFD}');
    }
    out
}

#[derive(Clone, Debug, Default)]
struct RenderedDoc {
    pieces: Vec<RenderedPiece>,
    buffers: HashMap<i64, BufferData>,
    piece_end_chars: Vec<u64>,
}

impl RenderedDoc {
    fn total_chars(&self) -> u64 {
        self.piece_end_chars.last().copied().unwrap_or(0)
    }

    fn snapshot(&self) -> Result<String> {
        let mut out = String::new();
        for piece in &self.pieces {
            if piece.coord.tombstone {
                continue;
            }
            let buffer = self.buffers.get(&piece.coord.buffer_id).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "piece {} references missing buffer {}",
                    piece.id, piece.coord.buffer_id
                ))
            })?;
            let start = piece.coord.start_byte as usize;
            let end = start
                .checked_add(piece.coord.len_bytes as usize)
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("piece {} byte range overflow", piece.id))
                })?;
            let slice = buffer.contents.get(start..end).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "piece {} range [{start}, {end}) extends past buffer {} bytes",
                    piece.id,
                    buffer.contents.len()
                ))
            })?;
            out.push_str(&decode_utf32le_lossy(slice));
        }
        Ok(out)
    }

    fn live_piece_at(&self, pos: u64) -> Result<(&RenderedPiece, u64)> {
        let idx = self
            .piece_end_chars
            .iter()
            .position(|&end| end > pos)
            .ok_or(SdkError::NotFound)?;
        let piece = &self.pieces[idx];
        if piece.coord.tombstone {
            return Err(SdkError::ValidationError(
                "live_piece_at landed on a tombstoned piece".into(),
            ));
        }
        let prev_end = if idx == 0 {
            0
        } else {
            self.piece_end_chars[idx - 1]
        };
        Ok((piece, pos - prev_end))
    }

    fn live_predecessor_for_insert(&self, pos: u64) -> Result<(&RenderedPiece, u64)> {
        let (piece, scalar_offset) = self.live_piece_at(pos)?;
        if scalar_offset > 0 {
            return Ok((piece, scalar_offset));
        }
        let pred = self.last_live_piece_before(pos).ok_or(SdkError::NotFound)?;
        Ok((pred, u64::from(pred_rendered_chars(pred)?)))
    }

    fn last_live_piece_before(&self, pos: u64) -> Option<&RenderedPiece> {
        let mut last: Option<&RenderedPiece> = None;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if piece.coord.tombstone {
                continue;
            }
            let end = self.piece_end_chars[idx];
            if end <= pos {
                last = Some(piece);
            } else {
                break;
            }
        }
        last
    }

    fn scalar_offset_to_piece_byte_offset(
        &self,
        piece: &RenderedPiece,
        scalar_offset: u64,
    ) -> Result<u32> {
        if !piece
            .coord
            .len_bytes
            .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
        {
            return Err(SdkError::ValidationError(format!(
                "piece {} len_bytes {} is not UTF-32 aligned",
                piece.id, piece.coord.len_bytes
            )));
        }
        if !self.buffers.contains_key(&piece.coord.buffer_id) {
            return Err(SdkError::ValidationError(format!(
                "piece {} references missing buffer {}",
                piece.id, piece.coord.buffer_id
            )));
        }
        let rendered_scalars = u64::from(piece.coord.len_bytes / PIECE_TEXT_UTF32_BYTES_PER_SCALAR);
        if scalar_offset > rendered_scalars {
            return Err(SdkError::NotFound);
        }
        let byte_offset = scalar_offset
            .checked_mul(u64::from(PIECE_TEXT_UTF32_BYTES_PER_SCALAR))
            .ok_or_else(|| SdkError::ValidationError("piece byte offset overflow".into()))?;
        u32::try_from(byte_offset)
            .map_err(|_| SdkError::ValidationError("piece byte offset exceeds u32".into()))
    }

    fn insert_coord_for_scalar_pos(&self, pos: u64) -> Result<BufferCoord> {
        if pos == 0 {
            return Ok(BufferCoord::DOCUMENT_START);
        }
        let total = self.total_chars();
        if pos > total {
            return Err(SdkError::NotFound);
        }
        if pos == total {
            let last = self.last_live_piece_before(pos).ok_or(SdkError::NotFound)?;
            let end_byte = last
                .coord
                .start_byte
                .checked_add(last.coord.len_bytes)
                .ok_or_else(|| SdkError::ValidationError("piece end byte overflow".into()))?;
            return Ok(BufferCoord {
                buffer_id: last.coord.buffer_id,
                byte_pos: end_byte,
            });
        }
        let (piece, scalar_offset) = self.live_predecessor_for_insert(pos)?;
        let byte_offset = self.scalar_offset_to_piece_byte_offset(piece, scalar_offset)?;
        let byte_pos = piece
            .coord
            .start_byte
            .checked_add(byte_offset)
            .ok_or_else(|| {
                SdkError::ValidationError("piece insert byte position overflow".into())
            })?;
        Ok(BufferCoord {
            buffer_id: piece.coord.buffer_id,
            byte_pos,
        })
    }

    fn endpoint_coord_for_scalar_pos(&self, pos: u64) -> Result<BufferCoord> {
        if pos == 0 {
            for piece in &self.pieces {
                if !piece.coord.tombstone {
                    return Ok(BufferCoord {
                        buffer_id: piece.coord.buffer_id,
                        byte_pos: piece.coord.start_byte,
                    });
                }
            }
            return Ok(BufferCoord::DOCUMENT_START);
        }
        self.insert_coord_for_scalar_pos(pos)
    }
}

const CLEARTEXT_CHUNK_BYTES: usize = 32 * 1024;
const CLEARTEXT_CHUNK_SCALARS: usize = CLEARTEXT_CHUNK_BYTES / UTF32_BYTES_PER_SCALAR;
const _: () = {
    assert!(CLEARTEXT_CHUNK_BYTES.is_multiple_of(UTF32_BYTES_PER_SCALAR));
    assert!(CLEARTEXT_CHUNK_BYTES < MAX_PIECETEXT_ENCRYPTED_BODY_BYTES);
};

fn chunk_for_insert(text: &str) -> Vec<&str> {
    debug_assert!(!text.is_empty());
    let mut chunks = Vec::new();
    let mut chunk_start = 0usize;
    let mut scalars_in_chunk = 0usize;
    for (byte_idx, _) in text.char_indices() {
        if scalars_in_chunk == CLEARTEXT_CHUNK_SCALARS {
            chunks.push(&text[chunk_start..byte_idx]);
            chunk_start = byte_idx;
            scalars_in_chunk = 0;
        }
        scalars_in_chunk += 1;
    }
    if chunk_start < text.len() {
        chunks.push(&text[chunk_start..]);
    }
    chunks
}

fn pred_rendered_chars(piece: &RenderedPiece) -> Result<u32> {
    if !piece
        .coord
        .len_bytes
        .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
    {
        return Err(SdkError::ValidationError(format!(
            "piece {} len_bytes {} is not UTF-32 aligned",
            piece.id, piece.coord.len_bytes
        )));
    }
    Ok(piece.coord.len_bytes / PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
}

#[derive(Default)]
pub(crate) struct PieceTextState {
    rendered: Option<RenderedDoc>,
    list_number: Option<i64>,
}

pub(crate) struct PieceTextCache {
    state: Mutex<PieceTextState>,
    stale: std::sync::atomic::AtomicBool,
}

impl PieceTextCache {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(PieceTextState::default()),
            stale: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn mark_stale(&self) {
        self.stale.store(true, std::sync::atomic::Ordering::Release);
    }
}

pub struct PieceTextArea {
    space: Arc<Space>,
    address: PieceTextAddress,
    cache: Arc<PieceTextCache>,
}

impl std::fmt::Debug for PieceTextArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PieceTextArea")
            .field("table", &self.address.table)
            .field("row_id", &self.address.row_id)
            .field("column", &self.address.column)
            .finish()
    }
}

impl PieceTextArea {
    pub(crate) fn with_cache(
        space: Arc<Space>,
        address: PieceTextAddress,
        cache: Arc<PieceTextCache>,
    ) -> Self {
        Self {
            space,
            address,
            cache,
        }
    }

    async fn resolve_list_number_locked(
        &self,
        state: &mut PieceTextState,
        commitment: &[u8; 32],
    ) -> Result<i64> {
        if let Some(ln) = state.list_number {
            return Ok(ln);
        }

        use encrypted_spaces_backend::query::{
            ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
        };

        let mut query = Query::new(
            self.address.table.clone(),
            QueryOperation::Select(vec![self.address.column.clone()]),
        );
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(self.address.row_id)],
            cursor_id: None,
        });
        let schemas = self.space.with_state(|state| state.table_schemas.clone());
        let verified = self
            .space
            .transport
            .select(query, commitment, &schemas)
            .await?;
        let row = verified
            .main_rows
            .into_iter()
            .next()
            .ok_or(SdkError::NotFound)?;
        let obj = row.as_object().ok_or_else(|| {
            SdkError::ValidationError(format!(
                "parent row {} of table '{}' is not a JSON object",
                self.address.row_id, self.address.table
            ))
        })?;
        let value = obj.get(&self.address.column).ok_or_else(|| {
            SdkError::ValidationError(format!(
                "column '{}' not found on parent row",
                self.address.column
            ))
        })?;
        let list_number = value.as_i64().ok_or_else(|| {
            SdkError::ValidationError(format!(
                "PieceText column '{}' is not an integer",
                self.address.column
            ))
        })?;
        if list_number <= 0 {
            return Err(SdkError::ValidationError(format!(
                "PieceText column '{}' has not been allocated",
                self.address.column
            )));
        }

        state.list_number = Some(list_number);
        Ok(list_number)
    }

    pub async fn sync(&self) -> Result<()> {
        let mut state = self.cache.state.lock().await;
        self.sync_locked(&mut state).await
    }

    async fn sync_locked(&self, state: &mut PieceTextState) -> Result<()> {
        self.cache
            .stale
            .store(false, std::sync::atomic::Ordering::Release);
        let result = self.sync_locked_inner(state).await;
        if result.is_err() {
            self.cache.mark_stale();
        }
        result
    }

    async fn sync_locked_inner(&self, state: &mut PieceTextState) -> Result<()> {
        match self.sync_locked_attempt(state).await {
            Ok(()) => Ok(()),
            Err(SdkError::FastForwardRequired { .. }) => {
                self.space.recover_via_fast_forward().await?;
                state.list_number = None;
                self.sync_locked_attempt(state).await
            }
            Err(e) => Err(e),
        }
    }

    async fn sync_locked_attempt(&self, state: &mut PieceTextState) -> Result<()> {
        let commitment = self.space.current_data_commitment();
        let list_number = self.resolve_list_number_locked(state, &commitment).await?;
        let rendered = self.fetch_rendered(list_number, &commitment).await?;
        state.rendered = Some(rendered);
        Ok(())
    }

    async fn ensure_initialized_locked(&self, state: &mut PieceTextState) -> Result<()> {
        let stale = self.cache.stale.load(std::sync::atomic::Ordering::Acquire);
        if state.rendered.is_none() || stale {
            self.sync_locked(state).await?;
        }
        Ok(())
    }

    async fn fetch_rendered(&self, list_number: i64, commitment: &[u8; 32]) -> Result<RenderedDoc> {
        use encrypted_spaces_backend::query::{
            ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
        };

        #[derive(Clone, Deserialize)]
        struct PieceRow {
            id: Option<i64>,
            list_number: Option<i64>,
            prev_id: Option<i64>,
            next_id: Option<i64>,
            buffer_id: Option<i64>,
            start_byte: Option<i64>,
            len_bytes: Option<i64>,
            tombstone: Option<i64>,
        }

        let mut query = Query::new(
            PIECE_COORDS_TABLE_NAME.to_string(),
            QueryOperation::Select(Vec::new()),
        );
        query.predicate = Some(Predicate {
            column: "list_number".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(list_number)],
            cursor_id: None,
        });
        let coord_schemas = self.space.with_state(|state| state.table_schemas.clone());
        let verified = self
            .space
            .transport
            .select(query, commitment, &coord_schemas)
            .await?;
        let rows: Vec<PieceRow> = verified
            .main_rows
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| {
                SdkError::SerializationError(format!(
                    "failed to deserialize _piecetext_pieces row: {e}"
                ))
            })?;

        let mut by_id: HashMap<i64, PieceRow> = HashMap::with_capacity(rows.len());
        let mut head_id: Option<i64> = None;
        let mut head_count = 0usize;
        for row in rows {
            let id = row
                .id
                .ok_or_else(|| SdkError::ValidationError("piece row missing id".into()))?;
            if id <= 0 {
                return Err(SdkError::ValidationError(format!(
                    "piece row has non-positive id {id}"
                )));
            }
            if row.list_number != Some(list_number) {
                return Err(SdkError::ValidationError(format!(
                    "piece row {id} has list_number {:?}, expected {list_number}",
                    row.list_number
                )));
            }
            let prev = row.prev_id.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing prev_id"))
            })?;
            row.next_id.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing next_id"))
            })?;
            if prev < 0 {
                return Err(SdkError::ValidationError(format!(
                    "piece row {id} has negative prev_id {prev}"
                )));
            }
            row.buffer_id.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing buffer_id"))
            })?;
            row.start_byte.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing start_byte"))
            })?;
            row.len_bytes.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing len_bytes"))
            })?;
            row.tombstone.ok_or_else(|| {
                SdkError::ValidationError(format!("piece row {id} missing tombstone"))
            })?;
            if prev == 0 {
                head_count += 1;
                head_id = Some(id);
            }
            by_id.insert(id, row);
        }

        let mut ordered: Vec<RenderedPiece> = Vec::with_capacity(by_id.len());
        if !by_id.is_empty() {
            if head_count != 1 {
                return Err(SdkError::ValidationError(format!(
                    "piece chain integrity error: expected exactly 1 head, found {head_count}"
                )));
            }
            let mut current = head_id.expect("head_count checked");
            let mut expected_prev: i64 = 0;
            let mut visited = 0usize;
            let total = by_id.len();
            loop {
                if visited >= total {
                    return Err(SdkError::ValidationError(
                        "piece chain integrity error: cycle detected".into(),
                    ));
                }
                let row = by_id.get(&current).ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "piece chain integrity error: row {current} not in fetched set"
                    ))
                })?;
                let prev = row.prev_id.expect("validated");
                let next = row.next_id.expect("validated");
                if prev != expected_prev {
                    return Err(SdkError::ValidationError(format!(
                        "piece chain integrity error: row {current} prev_id={prev}, expected {expected_prev}"
                    )));
                }
                let buffer_id = row.buffer_id.expect("validated");
                let start_byte = row.start_byte.expect("validated");
                let len_bytes = row.len_bytes.expect("validated");
                let tombstone_int = row.tombstone.expect("validated");
                if buffer_id <= 0 {
                    return Err(SdkError::ValidationError(format!(
                        "piece row {current} has non-positive buffer_id {buffer_id}"
                    )));
                }
                if !(0..=1).contains(&tombstone_int) {
                    return Err(SdkError::ValidationError(format!(
                        "piece row {current} has invalid tombstone {tombstone_int}"
                    )));
                }
                let start_byte_u32: u32 = start_byte.try_into().map_err(|_| {
                    SdkError::ValidationError(format!(
                        "piece row {current} has out-of-range start_byte {start_byte}"
                    ))
                })?;
                let len_bytes_u32: u32 = len_bytes.try_into().map_err(|_| {
                    SdkError::ValidationError(format!(
                        "piece row {current} has out-of-range len_bytes {len_bytes}"
                    ))
                })?;
                if len_bytes_u32 == 0 {
                    return Err(SdkError::ValidationError(format!(
                        "piece row {current} has zero len_bytes"
                    )));
                }
                if !start_byte_u32.is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
                    || !len_bytes_u32.is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
                {
                    return Err(SdkError::ValidationError(format!(
                        "piece row {current} has non-UTF-32-aligned range"
                    )));
                }
                ordered.push(RenderedPiece {
                    id: current,
                    coord: PieceCoord {
                        buffer_id,
                        start_byte: start_byte_u32,
                        len_bytes: len_bytes_u32,
                        tombstone: tombstone_int != 0,
                    },
                });
                visited += 1;
                if next == 0 {
                    break;
                }
                expected_prev = current;
                current = next;
            }
            if visited != total {
                return Err(SdkError::ValidationError(format!(
                    "piece chain integrity error: walked {visited} rows, fetched {total}"
                )));
            }
        }

        let buffer_ids: Vec<i64> = ordered
            .iter()
            .map(|p| p.coord.buffer_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let buffers = self.fetch_buffers(&buffer_ids, commitment).await?;

        let mut piece_end_chars: Vec<u64> = Vec::with_capacity(ordered.len());
        let mut acc_chars: u64 = 0;
        let mut ranges_by_buffer: HashMap<i64, Vec<(u32, u32)>> = HashMap::new();
        for piece in &ordered {
            let buffer = buffers.get(&piece.coord.buffer_id).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "piece {} references missing buffer {}",
                    piece.id, piece.coord.buffer_id
                ))
            })?;
            let end_byte = piece
                .coord
                .start_byte
                .checked_add(piece.coord.len_bytes)
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("piece {} byte range overflow", piece.id))
                })?;
            if end_byte as usize > buffer.contents.len() {
                return Err(SdkError::ValidationError(format!(
                    "piece {} extends past buffer {} bytes",
                    piece.id, piece.coord.buffer_id
                )));
            }
            ranges_by_buffer
                .entry(piece.coord.buffer_id)
                .or_default()
                .push((piece.coord.start_byte, end_byte));
            if !piece.coord.tombstone {
                let chars = u64::from(piece.coord.len_bytes / PIECE_TEXT_UTF32_BYTES_PER_SCALAR);
                acc_chars = acc_chars.checked_add(chars).ok_or_else(|| {
                    SdkError::ValidationError("rendered scalar length overflows u64".into())
                })?;
            }
            piece_end_chars.push(acc_chars);
        }

        for (buffer_id, mut ranges) in ranges_by_buffer {
            ranges.sort_by_key(|&(start, _)| start);
            for window in ranges.windows(2) {
                let (_, prev_end) = window[0];
                let (next_start, _) = window[1];
                if next_start < prev_end {
                    return Err(SdkError::ValidationError(format!(
                        "piece chain integrity error: buffer {buffer_id} has overlapping ranges"
                    )));
                }
            }
        }

        Ok(RenderedDoc {
            pieces: ordered,
            buffers,
            piece_end_chars,
        })
    }

    async fn fetch_buffers(
        &self,
        buffer_ids: &[i64],
        commitment: &[u8; 32],
    ) -> Result<HashMap<i64, BufferData>> {
        if buffer_ids.is_empty() {
            return Ok(HashMap::new());
        }

        use base64::Engine as _;
        use encrypted_spaces_backend::query::{
            ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
        };

        let mut buffers: HashMap<i64, BufferData> = HashMap::with_capacity(buffer_ids.len());
        let schemas = self.space.with_state(|state| state.table_schemas.clone());

        for &buffer_id in buffer_ids {
            let mut query = Query::new(
                BUFFERS_TABLE_NAME.to_string(),
                QueryOperation::Select(Vec::new()),
            );
            query.predicate = Some(Predicate {
                column: "id".to_string(),
                operator: ComparisonOperator::Equal,
                values: vec![QueryParam::Integer(buffer_id)],
                cursor_id: None,
            });
            let verified = self
                .space
                .transport
                .select(query, commitment, &schemas)
                .await?;
            let mut rows = verified.main_rows;
            decrypt_table_rows_strict(&mut rows, BUFFERS_TABLE_NAME, &schemas, &self.space).await?;
            let row = rows.into_iter().next().ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "buffer {buffer_id} not found while syncing PieceText"
                ))
            })?;
            let obj = row.as_object().ok_or_else(|| {
                SdkError::ValidationError(format!("buffer {buffer_id} is not a JSON object"))
            })?;
            let owner_table = obj
                .get("owner_table")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("buffer {buffer_id} missing owner_table"))
                })?;
            let owner_row_id = obj
                .get("owner_row_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("buffer {buffer_id} missing owner_row_id"))
                })?;
            let owner_column = obj
                .get("owner_column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("buffer {buffer_id} missing owner_column"))
                })?;
            if owner_table != self.address.table
                || owner_row_id != self.address.row_id
                || owner_column != self.address.column
            {
                return Err(SdkError::ValidationError(format!(
                    "buffer {buffer_id} owner mismatch for PieceText document"
                )));
            }
            let len_bytes = obj
                .get("len_bytes")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!("buffer {buffer_id} missing len_bytes"))
                })?;
            let len_bytes_u32: u32 = len_bytes.try_into().map_err(|_| {
                SdkError::ValidationError(format!(
                    "buffer {buffer_id} has out-of-range len_bytes {len_bytes}"
                ))
            })?;
            if !len_bytes_u32.is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR) {
                return Err(SdkError::ValidationError(format!(
                    "buffer {buffer_id} len_bytes {len_bytes_u32} is not UTF-32 aligned"
                )));
            }
            let contents_b64 = obj
                .get("contents")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "buffer {buffer_id} contents missing or not a string after decrypt"
                    ))
                })?;
            let contents_bytes = base64::engine::general_purpose::STANDARD
                .decode(contents_b64)
                .map_err(|e| {
                    SdkError::ValidationError(format!(
                        "buffer {buffer_id} contents are not valid base64 after decrypt: {e}"
                    ))
                })?;
            if contents_bytes.len() != len_bytes_u32 as usize {
                return Err(SdkError::ValidationError(format!(
                    "buffer {buffer_id} decrypted byte length {} does not match len_bytes {}",
                    contents_bytes.len(),
                    len_bytes_u32
                )));
            }
            buffers.insert(
                buffer_id,
                BufferData {
                    contents: contents_bytes,
                },
            );
        }
        Ok(buffers)
    }

    pub async fn snapshot(&self) -> Result<String> {
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        state.rendered.as_ref().expect("synced").snapshot()
    }

    /// Return the currently rendered snapshot without refreshing a stale cell.
    ///
    /// This is a narrow integration hook for UI edits that were computed
    /// against a local baseline before a remote broadcast marked the document
    /// stale. The caller can use the returned text to translate UI offsets
    /// against the same baseline that the user edited, then submit coordinates
    /// with [`apply_diff_from_cached_snapshot`](Self::apply_diff_from_cached_snapshot).
    #[doc(hidden)]
    pub async fn snapshot_from_cached_render(&self) -> Result<Option<String>> {
        let state = self.cache.state.lock().await;
        match state.rendered.as_ref() {
            Some(rendered) => rendered.snapshot().map(Some),
            None => Ok(None),
        }
    }

    /// Number of Unicode scalars (chars) in the rendered document.
    pub async fn len(&self) -> Result<usize> {
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        let total = state.rendered.as_ref().expect("synced").total_chars();
        usize::try_from(total)
            .map_err(|_| SdkError::ValidationError("document length exceeds usize::MAX".into()))
    }

    pub async fn insert_string(&self, pos: usize, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        let coord = state
            .rendered
            .as_ref()
            .expect("synced")
            .insert_coord_for_scalar_pos(pos as u64)?;
        self.insert_at_coord_locked(&mut state, coord, s)
            .await
            .map(|_| ())
    }

    /// Like [`insert_string`](Self::insert_string), but if the document is
    /// already rendered locally it preserves that cached baseline even when a
    /// remote broadcast has marked the cell stale.
    #[doc(hidden)]
    pub async fn insert_string_from_cached_snapshot(&self, pos: usize, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let mut state = self.cache.state.lock().await;
        if state.rendered.is_none() {
            self.sync_locked(&mut state).await?;
        }
        let coord = state
            .rendered
            .as_ref()
            .expect("rendered")
            .insert_coord_for_scalar_pos(pos as u64)?;
        self.insert_at_coord_locked(&mut state, coord, s)
            .await
            .map(|_| ())
    }

    pub async fn append_string(&self, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        let total = state.rendered.as_ref().expect("synced").total_chars();
        let coord = state
            .rendered
            .as_ref()
            .expect("synced")
            .insert_coord_for_scalar_pos(total)?;
        self.insert_at_coord_locked(&mut state, coord, s)
            .await
            .map(|_| ())
    }

    pub async fn delete_range(&self, start: usize, end: usize) -> Result<()> {
        if start > end {
            return Err(SdkError::ValidationError(format!(
                "delete_range: start ({start}) > end ({end})"
            )));
        }
        if start == end {
            return Ok(());
        }
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        let (start_coord, end_coord) = {
            let doc = state.rendered.as_ref().expect("synced");
            let total = doc.total_chars();
            if (start as u64) > total || (end as u64) > total {
                return Err(SdkError::NotFound);
            }
            let s = doc.endpoint_coord_for_scalar_pos(start as u64)?;
            let e = doc.endpoint_coord_for_scalar_pos(end as u64)?;
            (s, e)
        };
        self.delete_coord_range_locked(&mut state, start_coord, end_coord)
            .await
    }

    /// Like [`delete_range`](Self::delete_range), but preserves an existing
    /// cached rendered baseline even when the cell is stale.
    #[doc(hidden)]
    pub async fn delete_range_from_cached_snapshot(&self, start: usize, end: usize) -> Result<()> {
        if start > end {
            return Err(SdkError::ValidationError(format!(
                "delete_range: start ({start}) > end ({end})"
            )));
        }
        if start == end {
            return Ok(());
        }
        let mut state = self.cache.state.lock().await;
        if state.rendered.is_none() {
            self.sync_locked(&mut state).await?;
        }
        let (start_coord, end_coord) = {
            let doc = state.rendered.as_ref().expect("rendered");
            let total = doc.total_chars();
            if (start as u64) > total || (end as u64) > total {
                return Err(SdkError::NotFound);
            }
            let s = doc.endpoint_coord_for_scalar_pos(start as u64)?;
            let e = doc.endpoint_coord_for_scalar_pos(end as u64)?;
            (s, e)
        };
        self.delete_coord_range_locked(&mut state, start_coord, end_coord)
            .await
    }

    /// Low-level coordinate-protocol write: insert `text` anchored at the
    /// buffer coordinate `at`, returning the anchor coordinate. Concurrent
    /// inserts at the same coordinate render newest-first (LIFO).
    ///
    /// This is the raw coordinate surface beneath
    /// [`insert_string`](Self::insert_string)/[`append_string`](Self::append_string);
    /// it is exposed only for the piece-text coordinate-protocol test suite and
    /// is intentionally kept out of the documented public API. Most callers
    /// should use the scalar-indexed methods.
    #[doc(hidden)]
    pub async fn insert_at_coord(&self, at: BufferCoord, text: &str) -> Result<BufferCoord> {
        if text.is_empty() {
            return Ok(at);
        }
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        self.insert_at_coord_locked(&mut state, at, text).await
    }

    /// Low-level coordinate-protocol write: delete the span between buffer
    /// coordinates `start` and `end`.
    ///
    /// Companion to [`insert_at_coord`](Self::insert_at_coord); see that method
    /// for why this raw surface is `#[doc(hidden)]`.
    #[doc(hidden)]
    pub async fn delete_coord_range(&self, start: BufferCoord, end: BufferCoord) -> Result<()> {
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        self.delete_coord_range_locked(&mut state, start, end).await
    }

    pub async fn apply_diff(&self, pos: usize, delete_count: usize, inserted: &str) -> Result<()> {
        if delete_count == 0 {
            return self.insert_string(pos, inserted).await;
        }
        if inserted.is_empty() {
            let end = pos.checked_add(delete_count).ok_or_else(|| {
                SdkError::ValidationError("apply_diff: delete range overflow".into())
            })?;
            return self.delete_range(pos, end).await;
        }

        let end = pos
            .checked_add(delete_count)
            .ok_or_else(|| SdkError::ValidationError("apply_diff: delete range overflow".into()))?;
        let mut state = self.cache.state.lock().await;
        self.ensure_initialized_locked(&mut state).await?;
        let (start_coord, end_coord, insert_anchor) = {
            let doc = state.rendered.as_ref().expect("synced");
            let total = doc.total_chars();
            if (pos as u64) > total || (end as u64) > total {
                return Err(SdkError::NotFound);
            }
            let s = doc.endpoint_coord_for_scalar_pos(pos as u64)?;
            let e = doc.endpoint_coord_for_scalar_pos(end as u64)?;
            let insert_anchor = if pos == 0 {
                BufferCoord::DOCUMENT_START
            } else {
                s
            };
            (s, e, insert_anchor)
        };
        self.apply_replacement_locked(&mut state, start_coord, end_coord, insert_anchor, inserted)
            .await
    }

    /// Like [`apply_diff`](Self::apply_diff), but preserves an existing cached
    /// rendered baseline even when the cell is stale.
    #[doc(hidden)]
    pub async fn apply_diff_from_cached_snapshot(
        &self,
        pos: usize,
        delete_count: usize,
        inserted: &str,
    ) -> Result<()> {
        if delete_count == 0 {
            return self.insert_string_from_cached_snapshot(pos, inserted).await;
        }
        if inserted.is_empty() {
            let end = pos.checked_add(delete_count).ok_or_else(|| {
                SdkError::ValidationError("apply_diff: delete range overflow".into())
            })?;
            return self.delete_range_from_cached_snapshot(pos, end).await;
        }

        let end = pos
            .checked_add(delete_count)
            .ok_or_else(|| SdkError::ValidationError("apply_diff: delete range overflow".into()))?;
        let mut state = self.cache.state.lock().await;
        if state.rendered.is_none() {
            self.sync_locked(&mut state).await?;
        }
        let (start_coord, end_coord, insert_anchor) = {
            let doc = state.rendered.as_ref().expect("rendered");
            let total = doc.total_chars();
            if (pos as u64) > total || (end as u64) > total {
                return Err(SdkError::NotFound);
            }
            let s = doc.endpoint_coord_for_scalar_pos(pos as u64)?;
            let e = doc.endpoint_coord_for_scalar_pos(end as u64)?;
            let insert_anchor = if pos == 0 {
                BufferCoord::DOCUMENT_START
            } else {
                s
            };
            (s, e, insert_anchor)
        };
        self.apply_replacement_locked(&mut state, start_coord, end_coord, insert_anchor, inserted)
            .await
    }

    async fn apply_replacement_locked(
        &self,
        state: &mut PieceTextState,
        start_coord: BufferCoord,
        end_coord: BufferCoord,
        insert_anchor: BufferCoord,
        inserted: &str,
    ) -> Result<()> {
        let chunks = chunk_for_insert(inserted);
        if chunks.len() > MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT {
            return Err(SdkError::ValidationError(format!(
                "atomic replacement requires {} inserted chunks, exceeding chunk limit {MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT}",
                chunks.len()
            )));
        }

        let mut ops = Vec::with_capacity(1 + chunks.len());
        let mut hashed_values = HashedValues::new();
        ops.push(PieceTextEditItemManifest::Delete {
            start: start_coord,
            end: end_coord,
        });

        for chunk in chunks.iter().rev() {
            let cleartext = encode_utf32le(chunk);
            let (manifest, stored_value) = self.encrypt_inserted_body(&cleartext).await?;
            hashed_values.insert(manifest.ciphertext_value_hash, stored_value);
            ops.push(PieceTextEditItemManifest::Insert {
                at: insert_anchor,
                inserted: manifest,
            });
        }

        self.submit_edit_locked(state, ops, hashed_values).await
    }

    async fn insert_at_coord_locked(
        &self,
        state: &mut PieceTextState,
        at: BufferCoord,
        text: &str,
    ) -> Result<BufferCoord> {
        let chunks = chunk_for_insert(text);
        if chunks.len() > MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT {
            return Err(SdkError::ValidationError(format!(
                "atomic insert requires {} inserted chunks, exceeding chunk limit {MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT}",
                chunks.len()
            )));
        }

        let mut ops = Vec::with_capacity(chunks.len());
        let mut hashed_values = HashedValues::new();

        for chunk in chunks.iter().rev() {
            let cleartext = encode_utf32le(chunk);
            let (manifest, stored_value) = self.encrypt_inserted_body(&cleartext).await?;
            hashed_values.insert(manifest.ciphertext_value_hash, stored_value);
            ops.push(PieceTextEditItemManifest::Insert {
                at,
                inserted: manifest,
            });
        }

        self.submit_edit_locked(state, ops, hashed_values).await?;
        Ok(at)
    }

    async fn delete_coord_range_locked(
        &self,
        state: &mut PieceTextState,
        start: BufferCoord,
        end: BufferCoord,
    ) -> Result<()> {
        let ops = vec![PieceTextEditItemManifest::Delete { start, end }];
        self.submit_edit_locked(state, ops, HashedValues::new())
            .await
    }

    async fn encrypt_inserted_body(
        &self,
        cleartext: &[u8],
    ) -> Result<(InsertedBufferManifest, Vec<u8>)> {
        use base64::Engine as _;
        let key = current_encryption_key(&self.space).await?;
        if !cleartext.len().is_multiple_of(UTF32_BYTES_PER_SCALAR) {
            return Err(SdkError::ValidationError(
                "inserted UTF-32 body is not 4-byte aligned".to_string(),
            ));
        }
        let ciphertext = encrypt_field(cleartext, &key);
        let len_bytes = u32::try_from(cleartext.len())
            .map_err(|_| SdkError::ValidationError("inserted text length exceeds u32".into()))?;
        let ciphertext_len = u32::try_from(ciphertext.len())
            .map_err(|_| SdkError::ValidationError("ciphertext length exceeds u32".into()))?;
        let stored = encrypted_spaces_backend::merk_storage::stored_value::value_to_bytes(
            &serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            ),
        )
        .map_err(|e| {
            SdkError::SerializationError(format!("failed to compute stored buffer bytes: {e}"))
        })?;
        let value_hash = encrypted_spaces_storage_encoding::hashstore_hash(&stored);
        let manifest = InsertedBufferManifest {
            len_bytes,
            ciphertext_len,
            ciphertext_value_hash: value_hash,
        };
        Ok((manifest, stored))
    }

    fn fresh_op_id() -> [u8; 16] {
        use rand::TryRngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .expect("OS RNG failed");
        id
    }

    fn auth_state(&self) -> Result<(u32, u32, u32, [u8; 32])> {
        self.space.with_state(|state| {
            let uid = state
                .auth_context
                .uid
                .ok_or_else(|| SdkError::DatabaseError("user is not authenticated".into()))?;
            let uid = u32::try_from(uid).map_err(|_| {
                SdkError::ValidationError(format!("authenticated uid {uid} is out of range"))
            })?;
            Ok((
                uid,
                state.current_change_id,
                state.my_last_change_id,
                state.current_clc_state.root.into(),
            ))
        })
    }

    async fn submit_edit_locked(
        &self,
        state: &mut PieceTextState,
        ops: Vec<PieceTextEditItemManifest>,
        hashed_values: HashedValues,
    ) -> Result<()> {
        let (uid, parent_change, sig_ref, parent_clc) = self.auth_state()?;
        let envelope = PieceTextEditEnvelopeV1 {
            version: PIECE_TEXT_ENVELOPE_VERSION_V1,
            op_id: Self::fresh_op_id(),
            address: self.address.clone(),
            edit: PieceTextEditManifest { ops },
        };
        envelope.validate().map_err(|e| {
            SdkError::ValidationError(format!("invalid PieceTextEdit envelope: {e}"))
        })?;
        let message = envelope.changelog_message().map_err(|e| {
            SdkError::SerializationError(format!("failed to build PieceTextEdit message: {e}"))
        })?;
        let mut entry = ChangelogEntry {
            timestamp: ChangelogEntry::get_unix_timestamp(),
            uid,
            parent_change,
            message,
            sig_ref,
            parent_clc,
            signature: Vec::new(),
        };
        {
            let km = self.space.key_manager.lock().await;
            encrypted_spaces_backend::sign_change::sign_change(&mut entry, km.auth_key_pair());
        }

        let change = Change {
            entry,
            hashed_values,
        };
        let (change, response) = self
            .space
            .submit_change_with_ff_retry(change)
            .await
            .map_err(map_piece_text_submit_error)?;

        match self
            .space
            .validate_and_apply_change(&change.entry, &response)
        {
            Ok(_writes) => {
                self.invalidate_internal_caches();
                self.sync_locked(state).await?;
            }
            Err(SdkError::FastForwardRequired { .. }) => {
                self.space.recover_via_fast_forward().await?;
                self.invalidate_internal_caches();
                self.sync_locked(state).await?;
            }
            Err(e) => return Err(map_piece_text_submit_error(e)),
        }
        Ok(())
    }

    fn invalidate_internal_caches(&self) {
        self.space.with_state_mut(|state| {
            state.cache.invalidate_table(PIECE_COORDS_TABLE_NAME);
            state.cache.invalidate_table(BUFFERS_TABLE_NAME);
        });
    }
}

fn map_piece_text_submit_error(error: SdkError) -> SdkError {
    match error {
        SdkError::DatabaseError(msg)
            if msg.contains("MAX_PIECETEXT")
                || msg.contains("PieceText edit rejected by verifier limit")
                || msg.contains("document full")
                || msg.contains("piece count") =>
        {
            SdkError::ValidationError(format!("PieceText edit rejected by verifier limit: {msg}"))
        }
        other => other,
    }
}

impl Space {
    pub(crate) fn initialize_piece_text(&self) {
        self.register_table_schema(
            encrypted_spaces_backend::internal_schemas::piece_coords_schema(),
        );
        self.register_table_schema(encrypted_spaces_backend::internal_schemas::buffers_schema());
    }

    pub(crate) fn mark_all_piece_text_caches_stale(&self) {
        let caches = self
            .piece_text_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for cache in caches.values() {
            cache.mark_stale();
        }
    }

    pub(crate) fn invalidate_piece_text_caches_for_change(&self, entry: &ChangelogEntry) {
        if entry.message.op_type != OpType::PieceTextEdit {
            return;
        }
        let address = entry.message.entries.first().and_then(|kv| {
            match encrypted_spaces_backend::merk_storage::parse_key(&kv.key) {
                Ok(encrypted_spaces_backend::merk_storage::ParsedKey::PieceTextEdit {
                    table,
                    row_id,
                    column,
                    ..
                }) => Some(PieceTextAddress {
                    table,
                    row_id,
                    column,
                }),
                _ => None,
            }
        });

        self.with_state_mut(|state| {
            if let Some(addr) = address.as_ref() {
                state.cache.invalidate_table(&addr.table);
            }
            state.cache.invalidate_table(PIECE_COORDS_TABLE_NAME);
            state.cache.invalidate_table(BUFFERS_TABLE_NAME);
        });

        if let Some(addr) = address {
            let caches = self
                .piece_text_caches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cache) = caches.get(&addr) {
                cache.mark_stale();
            }
        }
    }

    pub fn piece_text(&self, table: &str, row_id: i64, column: &str) -> PieceTextArea {
        let address = PieceTextAddress {
            table: table.to_string(),
            row_id,
            column: column.to_string(),
        };
        let cache = {
            let mut caches = self
                .piece_text_caches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(
                caches
                    .entry(address.clone())
                    .or_insert_with(|| Arc::new(PieceTextCache::new())),
            )
        };
        PieceTextArea::with_cache(Arc::new(self.clone()), address, cache)
    }
}

pub(crate) fn piece_text_values_sidecar_for_wire(change: &Change) -> Option<Result<Vec<Vec<u8>>>> {
    if change.entry.message.op_type != OpType::PieceTextEdit {
        return None;
    }
    Some(piece_text_values_sidecar_for_wire_inner(change))
}

fn piece_text_values_sidecar_for_wire_inner(change: &Change) -> Result<Vec<Vec<u8>>> {
    use base64::Engine as _;

    let envelope = PieceTextEditEnvelopeV1::decode_from_entry(&change.entry)
        .map_err(|e| SdkError::ValidationError(format!("invalid PieceTextEdit change: {e}")))?;
    let mut out = Vec::with_capacity(envelope.edit.insert_count());
    for op in &envelope.edit.ops {
        let PieceTextEditItemManifest::Insert { inserted, .. } = op else {
            continue;
        };
        let stored = change
            .hashed_values
            .get(&inserted.ciphertext_value_hash)
            .ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "PieceTextEdit is missing inserted buffer material {}",
                    hex::encode(inserted.ciphertext_value_hash)
                ))
            })?;
        let value = encrypted_spaces_backend::merk_storage::stored_value::bytes_to_value(stored)
            .map_err(|e| {
                SdkError::SerializationError(format!(
                    "failed to decode PieceText stored buffer value: {e}"
                ))
            })?;
        let encoded = value.as_str().ok_or_else(|| {
            SdkError::ValidationError("PieceText stored buffer value is not a string".to_string())
        })?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| {
                SdkError::ValidationError(format!(
                    "PieceText stored buffer value is not base64: {e}"
                ))
            })?;
        out.push(raw);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_for_insert_preserves_order_and_boundaries() {
        let scalar = "a";
        let n = CLEARTEXT_CHUNK_SCALARS + 3;
        let input: String = (0..n).map(|_| scalar).collect();
        let chunks = chunk_for_insert(&input);
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|chunk| {
            encode_utf32le(chunk).len() <= CLEARTEXT_CHUNK_BYTES
                && encode_utf32le(chunk)
                    .len()
                    .is_multiple_of(UTF32_BYTES_PER_SCALAR)
        }));
        let joined: String = chunks.iter().copied().collect();
        assert_eq!(joined, input);
    }

    #[cfg(feature = "local-transport")]
    mod local_api_tests {
        use super::*;
        use crate::local_transport::LocalTransport;
        use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
        use encrypted_spaces_changelog_core::changelog::{Change, ChangelogEntry, HashedValues};
        use encrypted_spaces_changelog_core::piece_text_cleanup::{
            PieceTextCleanupBuffersEnvelopeV1, PieceTextCleanupPiecesEnvelopeV1,
            PieceTextCleanupRunV1, PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
        };
        use serde::Serialize;
        use serde_json::json;
        use std::sync::atomic::Ordering;

        #[derive(Serialize)]
        struct Doc {
            id: Option<i64>,
            title: String,
            body: i64,
        }

        async fn create_area() -> Result<(Space, PieceTextArea)> {
            let transport = LocalTransport::in_memory().await?;
            let root = transport.get_root_hash().await?;
            let space = Space::create(
                transport,
                ApplicationSchema::WithDataCommitment(
                    vec![],
                    root,
                    encrypted_spaces_ffproof::EXTEND_FF_ID,
                ),
            )
            .await?;
            let schema = SchemaBuilder::new("piecetext_docs")
                .column("id", ColumnType::Integer)
                .plaintext_primary_key()
                .column("title", ColumnType::String)?
                .plaintext()
                .column("body", ColumnType::PieceText)?
                .build()?;
            space.create_table(&schema).await?;
            let docs = space.table::<Doc>("piecetext_docs");
            let row_id = docs
                .insert(&Doc {
                    id: None,
                    title: "doc".to_string(),
                    body: 0,
                })
                .execute()
                .await?;
            let area = space.piece_text("piecetext_docs", row_id, "body");
            Ok((space, area))
        }

        #[derive(Clone, Copy)]
        enum CleanupEntryKind {
            Pieces,
            Buffers,
        }

        impl CleanupEntryKind {
            fn label(self) -> &'static str {
                match self {
                    Self::Pieces => "PieceTextCleanupPieces",
                    Self::Buffers => "PieceTextCleanupBuffers",
                }
            }
        }

        fn cleanup_entry_kinds() -> [CleanupEntryKind; 2] {
            [CleanupEntryKind::Pieces, CleanupEntryKind::Buffers]
        }

        fn cleanup_change_for_area(area: &PieceTextArea, kind: CleanupEntryKind) -> Change {
            let address = area.address.clone();
            let message = match kind {
                CleanupEntryKind::Pieces => PieceTextCleanupPiecesEnvelopeV1 {
                    version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
                    address,
                    list_number: 1,
                    op_id: 9,
                    runs: vec![PieceTextCleanupRunV1 { removals: vec![12] }],
                }
                .changelog_message()
                .unwrap(),
                CleanupEntryKind::Buffers => PieceTextCleanupBuffersEnvelopeV1 {
                    version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
                    address,
                    op_id: 9,
                    buffer_removals: vec![21],
                }
                .changelog_message()
                .unwrap(),
            };
            Change {
                entry: ChangelogEntry {
                    timestamp: 1000,
                    uid: 0,
                    parent_change: 8,
                    message,
                    sig_ref: 0,
                    parent_clc: [0u8; 32],
                    signature: vec![],
                },
                hashed_values: HashedValues::new(),
            }
        }

        #[tokio::test]
        async fn piecetext_area_append_insert_delete_snapshot() -> Result<()> {
            let (_space, area) = create_area().await?;

            area.sync().await?;
            assert_eq!(area.snapshot().await?, "");

            area.append_string("hello").await?;
            area.insert_string(5, " world").await?;
            assert_eq!(area.snapshot().await?, "hello world");

            area.delete_range(5, 6).await?;
            assert_eq!(area.snapshot().await?, "helloworld");
            Ok(())
        }

        #[tokio::test]
        async fn piecetext_area_apply_diff_replaces_range() -> Result<()> {
            let (_space, area) = create_area().await?;

            area.append_string("abcdef").await?;
            area.apply_diff(2, 3, "XY").await?;

            assert_eq!(area.snapshot().await?, "abXYf");
            Ok(())
        }

        #[tokio::test]
        async fn cleanup_broadcasts_leave_piece_text_cache_valid() -> Result<()> {
            let (space, area) = create_area().await?;

            area.append_string("cleanup-visible text").await?;
            assert_eq!(area.snapshot().await?, "cleanup-visible text");
            assert!(
                !area.cache.stale.load(Ordering::Acquire),
                "test setup should leave PieceText cache fresh"
            );

            for kind in cleanup_entry_kinds() {
                space.with_state_mut(|state| {
                    state.cache.init_table("piecetext_docs", &[]);
                    state.cache.insert_row(
                        "piecetext_docs",
                        json!({
                            "id": area.address.row_id,
                            "title": "cached row",
                            "body": 1,
                        }),
                    );
                    assert!(
                        state
                            .cache
                            .get_row("piecetext_docs", area.address.row_id)
                            .is_some(),
                        "{} test setup should populate parent table cache",
                        kind.label()
                    );
                });

                let change = cleanup_change_for_area(&area, kind);
                space.apply_broadcast_cache_updates(&change, &[]).await;

                assert!(
                    !area.cache.stale.load(Ordering::Acquire),
                    "{} should leave the targeted PieceText cache fresh",
                    kind.label()
                );
                assert!(
                    space.with_state(|state| state
                        .cache
                        .get_row("piecetext_docs", area.address.row_id)
                        .is_some()),
                    "{} should leave the addressed parent table cache alone",
                    kind.label()
                );
                assert_eq!(
                    area.snapshot().await?,
                    "cleanup-visible text",
                    "{} cleanup must not change visible PieceText contents",
                    kind.label()
                );
                assert!(
                    !area.cache.stale.load(Ordering::Acquire),
                    "{} snapshot should keep the cache fresh",
                    kind.label()
                );
            }
            Ok(())
        }
    }
}
