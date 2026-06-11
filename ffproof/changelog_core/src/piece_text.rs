use crate::changelog::{
    ChangelogEntry, ChangelogError, KvData, LogMessage, OpType, ROOT_TREE_PATH,
};
use encrypted_spaces_storage_encoding::keys::{parse_key, piece_text_edit_key, ParsedKey};
use serde::{Deserialize, Serialize};

pub use crate::piece_text_legacy_limits::*;

pub const PIECE_TEXT_ENVELOPE_VERSION_V1: u8 = 1;

/// Encoding decision: PieceText buffer plaintext is UTF-32LE.
///
/// Every plaintext Unicode scalar occupies exactly four bytes. The verifier
/// authenticates byte lengths and coordinates but not plaintext values, so the
/// no-split-character invariant is expressed as 4-byte alignment on all
/// `BufferCoord.byte_pos`, inserted buffer `len_bytes`, and derived
/// `PieceCoord` ranges.
pub const PIECE_TEXT_UTF32_BYTES_PER_SCALAR: u32 = 4;

/// Maximum Unicode scalar values carried by one PieceText buffer.
///
/// The previous UTF-8-era cleartext cap was 1 MiB, which allowed 1,048,576
/// ASCII/scalar characters. Preserve that effective character ceiling and
/// derive the UTF-32LE byte cap from it.
pub const MAX_PIECETEXT_BUFFER_CHARS: u32 = 1 << 20;

/// Cleartext UTF-32LE byte cap for `InsertedBufferManifest.len_bytes`.
pub const MAX_PIECETEXT_CLEAR_BUFFER_BYTES: u32 =
    MAX_PIECETEXT_BUFFER_CHARS * PIECE_TEXT_UTF32_BYTES_PER_SCALAR;

/// Legacy alias for existing planner/import sites; use
/// [`MAX_PIECETEXT_CLEAR_BUFFER_BYTES`] in new code.
pub const MAX_BUFFER_LEN_BYTES: u32 = MAX_PIECETEXT_CLEAR_BUFFER_BYTES;

/// Operational guardrails for piece-text edits.
///
/// These limits bound per-edit DoS surface and proof volume; they are not
/// semantic document limits. Larger pastes must be chunked into multiple
/// `PieceTextEdit` changes. The edit verifier resolves edit coordinates through
/// indexed `_piecetext_pieces.buffer_id` reads and authenticates only the piece
/// rows touched by planning.
///
/// This is the encrypted inserted-body cap (`ciphertext_len` and body bytes),
/// separate from [`MAX_PIECETEXT_CLEAR_BUFFER_BYTES`] because ciphertext/log
/// volume and cleartext coordinate range are distinct constraints.
pub const MAX_PIECETEXT_ENCRYPTED_BODY_BYTES: usize = 256 * 1024;

/// Legacy alias for existing SDK/import sites; use
/// [`MAX_PIECETEXT_ENCRYPTED_BODY_BYTES`] in new code.
pub const MAX_PIECETEXT_INSERTED_BUFFER_BYTES: usize = MAX_PIECETEXT_ENCRYPTED_BODY_BYTES;
pub const MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT: usize = 16;
pub const MAX_PIECETEXT_OPS_PER_EDIT: usize = 256;
pub const MAX_PIECETEXT_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_PIECETEXT_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PieceCoord {
    pub buffer_id: i64,
    pub start_byte: u32,
    pub len_bytes: u32,
    pub tombstone: bool,
}

impl PieceCoord {
    /// Reject a `_piecetext_pieces` coordinate whose `start_byte`/`len_bytes` do
    /// not lie on UTF-32 scalar boundaries (multiples of
    /// [`PIECE_TEXT_UTF32_BYTES_PER_SCALAR`]).
    ///
    /// The in-guest verifier authenticates byte lengths but never plaintext,
    /// so 4-byte alignment is the only way to prove no piece boundary splits a
    /// UTF-32 scalar. This is checked on every coordinate the verifier derives
    /// or reads back from the tree (defense-in-depth behind the envelope-input
    /// checks in [`BufferCoord::validate_shape`] and
    /// [`InsertedBufferManifest::validate`]).
    pub fn validate_utf32_alignment(&self) -> Result<(), ChangelogError> {
        if !self
            .start_byte
            .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
            || !self
                .len_bytes
                .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
        {
            return Err(ChangelogError::Generic(format!(
                "_piecetext_pieces coord is not UTF-32 aligned (start_byte={}, len_bytes={}); both must be multiples of {PIECE_TEXT_UTF32_BYTES_PER_SCALAR}",
                self.start_byte, self.len_bytes
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PieceTextAddress {
    pub table: String,
    pub row_id: i64,
    pub column: String,
}

impl PieceTextAddress {
    pub fn validate(&self) -> Result<(), ChangelogError> {
        validate_identifier("table", &self.table)?;
        validate_identifier("column", &self.column)?;
        if self.row_id <= 0 {
            return Err(ChangelogError::Generic(
                "PieceTextAddress.row_id must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BufferCoord {
    pub buffer_id: i64,
    pub byte_pos: u32,
}

impl BufferCoord {
    pub const DOCUMENT_START: BufferCoord = BufferCoord {
        buffer_id: 0,
        byte_pos: 0,
    };

    pub fn validate_shape(&self) -> Result<(), ChangelogError> {
        if self.buffer_id == 0 {
            if self.byte_pos == 0 {
                return Ok(());
            }
            return Err(ChangelogError::Generic(
                "DOCUMENT_START coordinate must use byte_pos 0".to_string(),
            ));
        }
        if self.buffer_id < 0 {
            return Err(ChangelogError::Generic(
                "BufferCoord.buffer_id must be positive or DOCUMENT_START".to_string(),
            ));
        }
        // UTF-32 teeth (primary): a malicious signer controls `byte_pos`
        // directly, so an unaligned endpoint here would let a raw envelope
        // split a 4-byte scalar. Reject anything off a scalar boundary.
        if !self
            .byte_pos
            .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
        {
            return Err(ChangelogError::Generic(format!(
                "BufferCoord.byte_pos {} is not a multiple of {PIECE_TEXT_UTF32_BYTES_PER_SCALAR} (UTF-32 scalar boundary)",
                self.byte_pos
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InsertedBufferManifest {
    pub len_bytes: u32,
    pub ciphertext_len: u32,
    pub ciphertext_value_hash: [u8; 32],
}

impl InsertedBufferManifest {
    pub fn validate(&self) -> Result<(), ChangelogError> {
        if self.len_bytes == 0 {
            return Err(ChangelogError::Generic(
                "Inserted buffer len_bytes must be greater than 0".to_string(),
            ));
        }
        if self.len_bytes > MAX_PIECETEXT_CLEAR_BUFFER_BYTES {
            return Err(ChangelogError::Generic(format!(
                "Inserted buffer len_bytes {} exceeds MAX_PIECETEXT_CLEAR_BUFFER_BYTES {MAX_PIECETEXT_CLEAR_BUFFER_BYTES}",
                self.len_bytes
            )));
        }
        // UTF-32 teeth (primary): the cleartext byte length is signer-supplied
        // and becomes the new piece's `len_bytes`. It must be a whole number of
        // 4-byte scalars so no inserted span can split a character.
        if !self
            .len_bytes
            .is_multiple_of(PIECE_TEXT_UTF32_BYTES_PER_SCALAR)
        {
            return Err(ChangelogError::Generic(format!(
                "Inserted buffer len_bytes {} is not a multiple of {PIECE_TEXT_UTF32_BYTES_PER_SCALAR} (UTF-32 scalar boundary)",
                self.len_bytes
            )));
        }
        if self.ciphertext_len == 0 {
            return Err(ChangelogError::Generic(
                "Inserted buffer ciphertext_len must be greater than 0".to_string(),
            ));
        }
        if self.ciphertext_len as usize > MAX_PIECETEXT_ENCRYPTED_BODY_BYTES {
            return Err(ChangelogError::Generic(format!(
                "Inserted buffer ciphertext_len {} exceeds MAX_PIECETEXT_ENCRYPTED_BODY_BYTES {MAX_PIECETEXT_ENCRYPTED_BODY_BYTES}",
                self.ciphertext_len
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PieceTextEditItemManifest {
    Insert {
        at: BufferCoord,
        inserted: InsertedBufferManifest,
    },
    Delete {
        start: BufferCoord,
        end: BufferCoord,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceTextEditManifest {
    pub ops: Vec<PieceTextEditItemManifest>,
}

impl PieceTextEditManifest {
    pub fn insert_count(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| matches!(op, PieceTextEditItemManifest::Insert { .. }))
            .count()
    }

    pub fn aggregate_ciphertext_len(&self) -> usize {
        self.ops
            .iter()
            .filter_map(|op| match op {
                PieceTextEditItemManifest::Insert { inserted, .. } => {
                    Some(inserted.ciphertext_len as usize)
                }
                PieceTextEditItemManifest::Delete { .. } => None,
            })
            .sum()
    }

    pub fn validate_size_caps(&self) -> Result<(), ChangelogError> {
        if self.ops.is_empty() {
            return Err(ChangelogError::Generic(
                "PieceTextEditManifest.ops must not be empty".to_string(),
            ));
        }
        if self.ops.len() > MAX_PIECETEXT_OPS_PER_EDIT {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditManifest has {} ops, exceeding MAX_PIECETEXT_OPS_PER_EDIT {MAX_PIECETEXT_OPS_PER_EDIT}",
                self.ops.len()
            )));
        }

        let insert_count = self.insert_count();
        if insert_count > MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditManifest has {insert_count} inserted buffers, exceeding MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT {MAX_PIECETEXT_INSERTED_BUFFERS_PER_EDIT}"
            )));
        }
        let aggregate_len = self.aggregate_ciphertext_len();
        if aggregate_len > MAX_PIECETEXT_BODY_BYTES {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditManifest body bytes {aggregate_len} exceeds MAX_PIECETEXT_BODY_BYTES {MAX_PIECETEXT_BODY_BYTES}"
            )));
        }

        for op in &self.ops {
            match op {
                PieceTextEditItemManifest::Insert { at, inserted } => {
                    at.validate_shape()?;
                    inserted.validate()?;
                }
                PieceTextEditItemManifest::Delete { start, end } => {
                    start.validate_shape()?;
                    end.validate_shape()?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceTextEditEnvelopeV1 {
    pub version: u8,
    pub op_id: [u8; 16],
    pub address: PieceTextAddress,
    pub edit: PieceTextEditManifest,
}

impl PieceTextEditEnvelopeV1 {
    pub fn validate(&self) -> Result<(), ChangelogError> {
        self.validate_with_canonical_len(None)
    }

    fn validate_with_canonical_len(
        &self,
        canonical_len: Option<usize>,
    ) -> Result<(), ChangelogError> {
        if self.version != PIECE_TEXT_ENVELOPE_VERSION_V1 {
            return Err(ChangelogError::Generic(format!(
                "unsupported PieceTextEditEnvelopeV1 version {}",
                self.version
            )));
        }
        self.address.validate()?;
        self.edit.validate_size_caps()?;

        let len = match canonical_len {
            Some(len) => len,
            None => self.canonical_bytes()?.len(),
        };
        if len > MAX_PIECETEXT_ENVELOPE_BYTES {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditEnvelopeV1 is {len} bytes, exceeding MAX_PIECETEXT_ENVELOPE_BYTES {MAX_PIECETEXT_ENVELOPE_BYTES}"
            )));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChangelogError> {
        postcard::to_allocvec(self).map_err(|e| {
            ChangelogError::Generic(format!("failed to serialize PieceTextEditEnvelopeV1: {e}"))
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChangelogError> {
        if bytes.len() > MAX_PIECETEXT_ENVELOPE_BYTES {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditEnvelopeV1 is {} bytes, exceeding MAX_PIECETEXT_ENVELOPE_BYTES {MAX_PIECETEXT_ENVELOPE_BYTES}",
                bytes.len()
            )));
        }

        let (envelope, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|e| {
                ChangelogError::Generic(format!("failed to decode PieceTextEditEnvelopeV1: {e}"))
            })?;
        if !trailing.is_empty() {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEditEnvelopeV1 has {} trailing bytes",
                trailing.len()
            )));
        }
        let canonical = envelope.canonical_bytes()?;
        if canonical != bytes {
            return Err(ChangelogError::Generic(
                "PieceTextEditEnvelopeV1 bytes are not canonical".to_string(),
            ));
        }
        envelope.validate_with_canonical_len(Some(canonical.len()))?;
        Ok(envelope)
    }

    pub fn validate_entry_key(&self, key: &[u8]) -> Result<(), ChangelogError> {
        match parse_key(key) {
            Ok(ParsedKey::PieceTextEdit {
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
            Ok(ParsedKey::PieceTextEdit { .. }) => Err(ChangelogError::KeyMismatch(
                "piece-text entry key does not match envelope address/op_id".to_string(),
            )),
            Ok(other) => Err(ChangelogError::KeyMismatch(format!(
                "piece-text entry key must use PT tag, got {other:?}"
            ))),
            Err(e) => Err(ChangelogError::KeyMismatch(format!(
                "failed to parse piece-text entry key: {e}"
            ))),
        }
    }

    pub fn decode_from_entry(entry: &ChangelogEntry) -> Result<Self, ChangelogError> {
        if entry.message.op_type != OpType::PieceTextEdit {
            return Err(ChangelogError::Generic(format!(
                "expected OpType::PieceTextEdit, got {:?}",
                entry.message.op_type
            )));
        }
        if entry.message.tree_path != ROOT_TREE_PATH {
            return Err(ChangelogError::Generic(
                "PieceTextEdit tree_path must be /".to_string(),
            ));
        }
        if entry.message.entries.len() != 1 {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit must carry exactly one manifest entry, got {}",
                entry.message.entries.len()
            )));
        }
        let kv = &entry.message.entries[0];
        // The manifest is stored inline at a dedicated `PT`-tagged key, so the
        // entry always carries the raw envelope bytes (never a hash reference).
        let envelope = Self::from_canonical_bytes(&kv.value)?;
        envelope.validate_entry_key(&kv.key)?;
        Ok(envelope)
    }

    pub fn changelog_entry_kv(&self) -> Result<KvData, ChangelogError> {
        Ok(KvData {
            key: piece_text_edit_key(
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
            op_type: OpType::PieceTextEdit,
            tree_path: ROOT_TREE_PATH.to_vec(),
            entries: vec![self.changelog_entry_kv()?],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPieceTextInsertedBody<T> {
    pub value_hash: [u8; 32],
    pub value: T,
}

pub fn validate_piece_text_inserted_bodies<T, F>(
    envelope: &PieceTextEditEnvelopeV1,
    inserted_bodies: &[Vec<u8>],
    mut value_for_body: F,
) -> Result<Vec<ValidatedPieceTextInsertedBody<T>>, ChangelogError>
where
    F: FnMut(usize, &[u8]) -> Result<ValidatedPieceTextInsertedBody<T>, ChangelogError>,
{
    let inserts: Vec<_> = envelope
        .edit
        .ops
        .iter()
        .filter_map(|op| match op {
            PieceTextEditItemManifest::Insert { inserted, .. } => Some(inserted),
            PieceTextEditItemManifest::Delete { .. } => None,
        })
        .collect();

    if inserted_bodies.len() != inserts.len() {
        return Err(ChangelogError::Generic(format!(
            "PieceTextEdit inserted body count {} does not match manifest insert count {}",
            inserted_bodies.len(),
            inserts.len()
        )));
    }

    let mut aggregate_len = 0usize;
    let mut validated = Vec::with_capacity(inserts.len());
    for (i, (manifest, body)) in inserts.iter().zip(inserted_bodies.iter()).enumerate() {
        aggregate_len = aggregate_len.checked_add(body.len()).ok_or_else(|| {
            ChangelogError::Generic(
                "PieceTextEdit inserted body aggregate length overflowed".to_string(),
            )
        })?;
        if aggregate_len > MAX_PIECETEXT_BODY_BYTES {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit inserted bodies total {aggregate_len} bytes exceeds MAX_PIECETEXT_BODY_BYTES {MAX_PIECETEXT_BODY_BYTES}"
            )));
        }
        if body.len() > MAX_PIECETEXT_ENCRYPTED_BODY_BYTES {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit inserted body {i} has {} bytes, exceeding MAX_PIECETEXT_ENCRYPTED_BODY_BYTES {MAX_PIECETEXT_ENCRYPTED_BODY_BYTES}",
                body.len()
            )));
        }
        if body.len() != manifest.ciphertext_len as usize {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit inserted body {i} has {} bytes, but manifest claims {}",
                body.len(),
                manifest.ciphertext_len
            )));
        }

        let body_value = value_for_body(i, body)?;
        if body_value.value_hash != manifest.ciphertext_value_hash {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit inserted body {i} value_hash {} does not match manifest {}",
                hex::encode(body_value.value_hash),
                hex::encode(manifest.ciphertext_value_hash)
            )));
        }
        validated.push(body_value);
    }

    Ok(validated)
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), ChangelogError> {
    let mut chars = value.chars();
    let first = chars.next().ok_or_else(|| {
        ChangelogError::Generic(format!("PieceTextAddress.{kind} must not be empty"))
    })?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(ChangelogError::Generic(format!(
            "PieceTextAddress.{kind} must start with an ASCII letter or underscore"
        )));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ChangelogError::Generic(format!(
            "PieceTextAddress.{kind} must contain only ASCII letters, digits, or underscores"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use encrypted_spaces_storage_encoding::keys::column_key;

    fn sample_envelope() -> PieceTextEditEnvelopeV1 {
        PieceTextEditEnvelopeV1 {
            version: PIECE_TEXT_ENVELOPE_VERSION_V1,
            op_id: [7u8; 16],
            address: PieceTextAddress {
                table: "channels".to_string(),
                row_id: 42,
                column: "notes_pieces".to_string(),
            },
            edit: PieceTextEditManifest {
                ops: vec![PieceTextEditItemManifest::Insert {
                    at: BufferCoord::DOCUMENT_START,
                    inserted: InsertedBufferManifest {
                        len_bytes: 4,
                        ciphertext_len: 64,
                        ciphertext_value_hash: [9u8; 32],
                    },
                }],
            },
        }
    }

    fn entry_with_kv(kv: KvData) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 2,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::PieceTextEdit,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![kv],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn envelope_round_trip_preserves_canonical_bytes() {
        let envelope = sample_envelope();
        let bytes = envelope.canonical_bytes().unwrap();
        let decoded = PieceTextEditEnvelopeV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn rejects_unknown_envelope_versions() {
        let mut envelope = sample_envelope();
        envelope.version = 2;
        let bytes = envelope.canonical_bytes().unwrap();
        let err = PieceTextEditEnvelopeV1::from_canonical_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_degenerate_addresses() {
        for envelope in [
            {
                let mut e = sample_envelope();
                e.address.table.clear();
                e
            },
            {
                let mut e = sample_envelope();
                e.address.column.clear();
                e
            },
            {
                let mut e = sample_envelope();
                e.address.row_id = 0;
                e
            },
        ] {
            let err = envelope.validate().unwrap_err();
            assert!(
                err.to_string().contains("PieceTextAddress"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn rejects_wrong_entry_key_tag() {
        let envelope = sample_envelope();
        let kv = KvData {
            key: column_key("channels", 42, "notes_pieces"),
            value: envelope.canonical_bytes().unwrap(),
        };
        let entry = entry_with_kv(kv);
        let err = PieceTextEditEnvelopeV1::decode_from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("PT tag"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_key_envelope_address_mismatch() {
        let envelope = sample_envelope();
        let kv = KvData {
            key: piece_text_edit_key("channels", 43, "notes_pieces", envelope.op_id),
            value: envelope.canonical_bytes().unwrap(),
        };
        let entry = entry_with_kv(kv);
        let err = PieceTextEditEnvelopeV1::decode_from_entry(&entry).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn rejects_oversized_insert_metadata() {
        let mut envelope = sample_envelope();
        if let PieceTextEditItemManifest::Insert { inserted, .. } = &mut envelope.edit.ops[0] {
            inserted.ciphertext_len = (MAX_PIECETEXT_ENCRYPTED_BODY_BYTES as u32) + 1;
        }
        let err = envelope.validate().unwrap_err();
        assert!(err.to_string().contains("ciphertext_len"));

        let mut envelope = sample_envelope();
        if let PieceTextEditItemManifest::Insert { inserted, .. } = &mut envelope.edit.ops[0] {
            inserted.len_bytes = MAX_PIECETEXT_CLEAR_BUFFER_BYTES + 1;
        }
        let err = envelope.validate().unwrap_err();
        assert!(err.to_string().contains("len_bytes"));
    }

    #[test]
    fn buffer_coord_rejects_unaligned_byte_pos() {
        let coord = BufferCoord {
            buffer_id: 5,
            byte_pos: 6,
        };
        let err = coord.validate_shape().unwrap_err();
        assert!(
            err.to_string().contains("multiple of 4"),
            "unexpected error: {err}"
        );
        // Aligned offset is accepted.
        BufferCoord {
            buffer_id: 5,
            byte_pos: 8,
        }
        .validate_shape()
        .unwrap();
    }

    #[test]
    fn inserted_manifest_rejects_unaligned_len_bytes() {
        let manifest = InsertedBufferManifest {
            len_bytes: 6,
            ciphertext_len: 64,
            ciphertext_value_hash: [0u8; 32],
        };
        let err = manifest.validate().unwrap_err();
        assert!(
            err.to_string().contains("multiple of 4"),
            "unexpected error: {err}"
        );
        // Aligned length is accepted.
        InsertedBufferManifest {
            len_bytes: 8,
            ciphertext_len: 64,
            ciphertext_value_hash: [0u8; 32],
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn piece_coord_alignment_check() {
        // Both fields aligned: ok.
        PieceCoord {
            buffer_id: 1,
            start_byte: 8,
            len_bytes: 4,
            tombstone: false,
        }
        .validate_utf32_alignment()
        .unwrap();
        // Misaligned start_byte: rejected.
        assert!(PieceCoord {
            buffer_id: 1,
            start_byte: 2,
            len_bytes: 4,
            tombstone: false,
        }
        .validate_utf32_alignment()
        .is_err());
        // Misaligned len_bytes: rejected.
        assert!(PieceCoord {
            buffer_id: 1,
            start_byte: 0,
            len_bytes: 5,
            tombstone: false,
        }
        .validate_utf32_alignment()
        .is_err());
    }
}
