use crate::changelog::{ChangelogEntry, ChangelogError, OpType, ROOT_TREE_PATH};
use crate::ops::{
    decode_i64_column_value, make_index_delete, make_index_put, next_id_after, next_id_put,
    read_auto_increment, read_indexed_row_ids, read_next_id, read_schema_columns,
    read_schema_indexes, validate_user_access, OpContext, OpReader, OpVerifier, OpVerifyResult,
};
use crate::tree_fs;
use crate::{ReadOp, WriteOp};
use encrypted_spaces_storage_encoding::keys::{column_key, native_marker_key, native_payload_key};
use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;
use std::collections::{BTreeSet, VecDeque};

pub const UPDATE_MESSAGE_KIND: u16 = 1;
pub const UPDATE_MESSAGE_VERSION: u16 = 1;
const NATIVE_HEADER_LEN: usize = 4;
const UPDATE_MESSAGE_PAYLOAD_LEN: usize = 40;
pub const RENAME_INODE_KIND: u16 = 9;
pub const RENAME_INODE_VERSION: u16 = 1;
const RENAME_INODE_PAYLOAD_FIXED_LEN: usize = 8 + 32 + 4;
const RENAME_INODE_MAX_MTIME_LEN: usize = 512;
const INODE_FOLDER: i64 = 2;
pub const MOVE_INODE_KIND: u16 = 10;
pub const MOVE_INODE_VERSION: u16 = 1;
const MOVE_INODE_PAYLOAD_FIXED_LEN: usize = 8 + 8 + 4;
const MOVE_INODE_MAX_MTIME_LEN: usize = 512;
const INODE_FILE: i64 = 1;
pub const ADD_INODE_KIND: u16 = 11;
pub const ADD_INODE_VERSION: u16 = 1;
const ADD_INODE_PAYLOAD_MIN_LEN: usize = 24 + 12 + 64 + 4;
pub const DELETE_INODE_RECURSIVE_KIND: u16 = 12;
pub const DELETE_INODE_RECURSIVE_VERSION: u16 = 1;
const DELETE_INODE_RECURSIVE_PAYLOAD_LEN: usize = 8;
const DELETE_INODE_RECURSIVE_MAX_NODES: usize = 4096;
const DELETE_INODE_RECURSIVE_MAX_DEPTH: usize = 1024;

// ─── Tree-fs native ops (Phase B) ───────────────────────────────────────────
// A separate filesystem surface: relative-inode records under the raw `/_fs`
// key namespace (see [`crate::tree_fs`]), written by hand-coded verifiers
// instead of the table-fs `inodes` SELECT/action path.
pub const TREE_FS_CREATE_KIND: u16 = 14;
pub const TREE_FS_CREATE_VERSION: u16 = 1;
pub const TREE_FS_RENAME_KIND: u16 = 15;
pub const TREE_FS_RENAME_VERSION: u16 = 1;
pub const TREE_FS_MOVE_KIND: u16 = 16;
pub const TREE_FS_MOVE_VERSION: u16 = 1;
pub const TREE_FS_DELETE_KIND: u16 = 17;
pub const TREE_FS_DELETE_VERSION: u16 = 1;
const TREE_FS_PATH_MAX_COMPONENTS: usize = tree_fs::MAX_CHILD_DEPTH;
const TREE_FS_PAYLOAD_MAX_VAR_LEN: usize = tree_fs::MAX_VAR_FIELD_LEN;

/// `tree_fs_create` payload (`/dir`+`/info` model): the parent inode path + the
/// new child's [`tree_fs::Inode`] value. The child id is **not** carried — the
/// verifier derives it from the accepted entry's `parent_clc`.
pub type TreeFsInodeCreatePayload = (tree_fs::InodePath, tree_fs::Inode);
/// `tree_fs_rename` payload (`/dir`+`/info` model): target inode path, new name,
/// new `mtime`.
pub type TreeFsInodeRenamePayload = (tree_fs::InodePath, Vec<u8>, i64);
/// `tree_fs_move` payload (`/dir`+`/info` model): source inode path, destination
/// parent inode path, new `mtime`.
pub type TreeFsInodeMovePayload = (tree_fs::InodePath, tree_fs::InodePath, i64);

/// Native op verifier.
pub(crate) struct NativeOp;

impl OpVerifier for NativeOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        validate_native_envelope(entry)?;

        let marker = &entry.message.entries[0];
        let payload = &entry.message.entries[1].value;
        let (kind, version) = decode_native_header(&marker.value)?;

        match (kind, version) {
            (UPDATE_MESSAGE_KIND, UPDATE_MESSAGE_VERSION) => update_message(entry, payload, reader),
            (RENAME_INODE_KIND, RENAME_INODE_VERSION) => rename_inode(entry, payload, reader),
            (MOVE_INODE_KIND, MOVE_INODE_VERSION) => move_inode(entry, payload, reader),
            (ADD_INODE_KIND, ADD_INODE_VERSION) => add_inode(entry, payload, reader, ctx),
            (DELETE_INODE_RECURSIVE_KIND, DELETE_INODE_RECURSIVE_VERSION) => {
                delete_inode_recursive(entry, payload, reader, ctx)
            }
            (TREE_FS_CREATE_KIND, TREE_FS_CREATE_VERSION) => tree_fs_create(entry, payload, reader),
            (TREE_FS_RENAME_KIND, TREE_FS_RENAME_VERSION) => tree_fs_rename(entry, payload, reader),
            (TREE_FS_MOVE_KIND, TREE_FS_MOVE_VERSION) => tree_fs_move(entry, payload, reader),
            (TREE_FS_DELETE_KIND, TREE_FS_DELETE_VERSION) => tree_fs_delete(entry, payload, reader),
            _ => Err(ChangelogError::Generic(format!(
                "native op: unknown native handler kind={kind} version={version}"
            ))),
        }
    }
}

fn validate_native_envelope(entry: &ChangelogEntry) -> Result<(), ChangelogError> {
    if entry.message.op_type != OpType::Native {
        return Err(ChangelogError::Generic(format!(
            "native op: expected OpType::Native, got {:?}",
            entry.message.op_type
        )));
    }

    if entry.message.tree_path != ROOT_TREE_PATH {
        return Err(ChangelogError::Generic(
            "native op: tree_path must be root '/'".to_string(),
        ));
    }

    if entry.message.entries.len() != 2 {
        return Err(ChangelogError::Generic(format!(
            "native op: expected exactly 2 kvs, got {}",
            entry.message.entries.len()
        )));
    }

    let marker_key = native_marker_key();
    if entry.message.entries[0].key != marker_key {
        return Err(ChangelogError::KeyMismatch(
            "native op: entry[0] key must be native_marker_key()".to_string(),
        ));
    }

    let payload_key = native_payload_key();
    if entry.message.entries[1].key != payload_key {
        return Err(ChangelogError::KeyMismatch(
            "native op: entry[1] key must be native_payload_key()".to_string(),
        ));
    }

    Ok(())
}

pub fn decode_native_header(bytes: &[u8]) -> Result<(u16, u16), ChangelogError> {
    if bytes.len() != NATIVE_HEADER_LEN {
        return Err(ChangelogError::Generic(format!(
            "native op: header must be {NATIVE_HEADER_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
    let version = u16::from_be_bytes([bytes[2], bytes[3]]);
    Ok((kind, version))
}

// ----------------------------------------------------------------------------
// Wire encoders. The verifier only ever decodes (it runs in the guest), but the
// SDK and the server's test fixtures must *construct* native envelopes. Each
// encoder is the byte-exact inverse of its `decode_*` sibling below; keeping the
// pair in the same file is what stops the wire format from drifting.
// ----------------------------------------------------------------------------

/// Encode the fixed 4-byte native header `[kind: u16_be][version: u16_be]`.
pub fn encode_native_header(kind: u16, version: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(NATIVE_HEADER_LEN);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out
}

/// Encode the fixed 40-byte `update_message` payload
/// `[message_id: i64_be][content_digest: [u8; 32]]`.
pub fn encode_update_message_payload(message_id: i64, content_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UPDATE_MESSAGE_PAYLOAD_LEN);
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(content_digest);
    out
}

/// Encode the variable-length `rename_inode` payload:
/// `[inode_id: i64_be][name_digest: [u8; 32]][mtime_len: u32_be][mtime: ciphertext]`.
///
/// `name` is hash-backed so only its 32-byte digest rides here (the bytes go in
/// the change sidecar); `mtime` is an **encrypted** Integer column whose
/// nondeterministic ciphertext can't be reconstructed from an `i64`, so the SDK
/// encrypts it client-side and its serialized bytes ride here verbatim,
/// length-prefixed.
pub fn encode_rename_inode_payload(
    inode_id: i64,
    name_digest: &[u8; 32],
    mtime_col_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RENAME_INODE_PAYLOAD_FIXED_LEN + mtime_col_bytes.len());
    out.extend_from_slice(&inode_id.to_be_bytes());
    out.extend_from_slice(name_digest);
    out.extend_from_slice(&(mtime_col_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(mtime_col_bytes);
    out
}

/// Encode the variable-length `move_inode` payload:
/// `[inode_id: i64_be][new_parent_id: i64_be][mtime_len: u32_be][mtime: ciphertext]`.
///
/// `parent_id` is a plaintext indexed integer and rides as an `i64`; `mtime` is
/// an encrypted Integer column whose serialized ciphertext rides here verbatim.
pub fn encode_move_inode_payload(
    inode_id: i64,
    new_parent_id: i64,
    mtime_col_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MOVE_INODE_PAYLOAD_FIXED_LEN + mtime_col_bytes.len());
    out.extend_from_slice(&inode_id.to_be_bytes());
    out.extend_from_slice(&new_parent_id.to_be_bytes());
    out.extend_from_slice(&(mtime_col_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(mtime_col_bytes);
    out
}

/// Encode the variable-length `add_inode` payload — the widest native insert:
/// `[parent_id: i64_be][author_id: i64_be][type: i64_be]`
/// `[size_len: u32_be][size: ciphertext]`
/// `[ctime_len: u32_be][ctime: ciphertext]`
/// `[mtime_len: u32_be][mtime: ciphertext]`
/// `[name_digest: [u8; 32]][mime_type_digest: [u8; 32]]`
/// `[file_hash_len: u32_be][file_hash: utf8 bytes]`.
///
/// `parent_id`/`author_id`/`type` are plaintext scalars; `size`/`ctime`/`mtime`
/// are **encrypted** Integer columns whose nondeterministic ciphertext rides
/// verbatim, each length-prefixed; `name`/`mime_type` are hash-backed Text
/// columns so only their 32-byte digests ride here (the encrypted bytes go in
/// the change sidecar); `file_hash` is a plaintext fileref column carrying the
/// hex SHA-256 of the pre-uploaded blob (the blob lives in the file store, not
/// the sidecar). Folder mode carries an all-zero `file_hash` and an empty
/// `mime_type`; both round-trip byte-for-byte.
#[allow(clippy::too_many_arguments)]
pub fn encode_add_inode_payload(
    parent_id: i64,
    author_id: i64,
    inode_type: i64,
    size_ciphertext: &[u8],
    ctime_ciphertext: &[u8],
    mtime_ciphertext: &[u8],
    name_digest: &[u8; 32],
    mime_type_digest: &[u8; 32],
    file_hash: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ADD_INODE_PAYLOAD_MIN_LEN
            + size_ciphertext.len()
            + ctime_ciphertext.len()
            + mtime_ciphertext.len()
            + file_hash.len(),
    );
    out.extend_from_slice(&parent_id.to_be_bytes());
    out.extend_from_slice(&author_id.to_be_bytes());
    out.extend_from_slice(&inode_type.to_be_bytes());
    out.extend_from_slice(&(size_ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(size_ciphertext);
    out.extend_from_slice(&(ctime_ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ctime_ciphertext);
    out.extend_from_slice(&(mtime_ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(mtime_ciphertext);
    out.extend_from_slice(name_digest);
    out.extend_from_slice(mime_type_digest);
    out.extend_from_slice(&(file_hash.len() as u32).to_be_bytes());
    out.extend_from_slice(file_hash.as_bytes());
    out
}

/// Encode the fixed 8-byte `delete_inode_recursive` payload `[inode_id: i64_be]`.
pub fn encode_delete_inode_recursive_payload(inode_id: i64) -> Vec<u8> {
    inode_id.to_be_bytes().to_vec()
}

fn update_message(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (message_id, content_digest) = decode_update_message_payload(payload)?;

    validate_user_access(entry, OpType::Native, "update_message", reader)?;

    let owner_key = column_key("messages", message_id, "user_id");
    let owner_read = reader.read(ReadOp::Key(owner_key.clone()))?;
    let (_, owner_value) = owner_read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "update_message: messages row_id={message_id} does not exist"
        ))
    })?;
    let owner = decode_i64_column_value(owner_value, "update_message", "messages.user_id")?;
    if owner != entry.uid as i64 {
        return Err(ChangelogError::AclDenied(format!(
            "update_message: uid={} cannot edit message owned by uid={owner}",
            entry.uid
        )));
    }

    Ok(OpVerifyResult {
        write_steps: vec![WriteOp::Put {
            key: column_key("messages", message_id, "content"),
            value: content_digest.to_vec(),
        }],
    })
}

pub fn decode_update_message_payload(bytes: &[u8]) -> Result<(i64, [u8; 32]), ChangelogError> {
    if bytes.len() != UPDATE_MESSAGE_PAYLOAD_LEN {
        return Err(ChangelogError::Generic(format!(
            "update_message: payload must be {UPDATE_MESSAGE_PAYLOAD_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&bytes[0..8]);
    let message_id = i64::from_be_bytes(id_bytes);

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[8..40]);

    Ok((message_id, digest))
}

fn rename_inode(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (inode_id, name_digest, mtime_col_bytes) = decode_rename_inode_payload(payload)?;

    validate_user_access(entry, OpType::Native, "rename_inode", reader)?;

    // Existence probe: presence check on `type` (present on every inode, never a
    // written column). A missing inode is a graceful no-op.
    let type_read = reader.read(ReadOp::Key(column_key("inodes", inode_id, "type")))?;
    if type_read.results.is_empty() {
        return Ok(OpVerifyResult {
            write_steps: vec![],
        });
    }

    // Applied in vector order (MRT/AVL is write-order sensitive): mtime then name.
    Ok(OpVerifyResult {
        write_steps: vec![
            WriteOp::Put {
                key: column_key("inodes", inode_id, "mtime"),
                value: mtime_col_bytes,
            },
            WriteOp::Put {
                key: column_key("inodes", inode_id, "name"),
                value: name_digest.to_vec(),
            },
        ],
    })
}

pub fn decode_rename_inode_payload(
    bytes: &[u8],
) -> Result<(i64, [u8; 32], Vec<u8>), ChangelogError> {
    if bytes.len() < RENAME_INODE_PAYLOAD_FIXED_LEN {
        return Err(ChangelogError::Generic(format!(
            "rename_inode: payload must be at least {RENAME_INODE_PAYLOAD_FIXED_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&bytes[0..8]);
    let inode_id = i64::from_be_bytes(id_bytes);

    let mut name_digest = [0u8; 32];
    name_digest.copy_from_slice(&bytes[8..40]);

    let mtime_len = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as usize;
    if mtime_len > RENAME_INODE_MAX_MTIME_LEN {
        return Err(ChangelogError::Generic(format!(
            "rename_inode: declared mtime ciphertext length {mtime_len} exceeds max {RENAME_INODE_MAX_MTIME_LEN}"
        )));
    }
    if bytes.len() != RENAME_INODE_PAYLOAD_FIXED_LEN + mtime_len {
        return Err(ChangelogError::Generic(format!(
            "rename_inode: payload length {} != fixed {RENAME_INODE_PAYLOAD_FIXED_LEN} + declared mtime {mtime_len}",
            bytes.len()
        )));
    }
    let mtime_col_bytes = bytes[RENAME_INODE_PAYLOAD_FIXED_LEN..].to_vec();

    Ok((inode_id, name_digest, mtime_col_bytes))
}

fn stored_i64_bytes(n: i64, column: &str, op_name: &str) -> Result<Vec<u8>, ChangelogError> {
    value_to_bytes(&serde_json::json!(n)).map_err(|e| {
        ChangelogError::Generic(format!("{op_name}: failed to serialize {column}={n}: {e}"))
    })
}

fn move_inode(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (inode_id, new_parent_id, mtime_col_bytes) = decode_move_inode_payload(payload)?;

    if inode_id == new_parent_id {
        return Err(ChangelogError::Generic(format!(
            "move_inode: inode_id={inode_id} cannot be its own parent"
        )));
    }

    if new_parent_id != 0 {
        let parent_type_read =
            reader.read(ReadOp::Key(column_key("inodes", new_parent_id, "type")))?;
        let (_, parent_type_value) = parent_type_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "move_inode: parent_id={new_parent_id} is not an existing folder"
            ))
        })?;
        let parent_type = decode_i64_column_value(parent_type_value, "move_inode", "inodes.type")?;
        if parent_type != INODE_FOLDER {
            return Err(ChangelogError::Generic(format!(
                "move_inode: parent_id={new_parent_id} has type {parent_type}, expected folder"
            )));
        }
    }

    validate_user_access(entry, OpType::Native, "move_inode", reader)?;

    let old_parent_read = reader.read(ReadOp::Key(column_key("inodes", inode_id, "parent_id")))?;
    let (_, old_parent_bytes) = old_parent_read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "move_inode: inodes row_id={inode_id} does not exist"
        ))
    })?;
    let new_parent_bytes = stored_i64_bytes(new_parent_id, "parent_id", "move_inode")?;

    // Applied in vector order (MRT/AVL is write-order sensitive).
    Ok(OpVerifyResult {
        write_steps: vec![
            WriteOp::Put {
                key: column_key("inodes", inode_id, "mtime"),
                value: mtime_col_bytes,
            },
            WriteOp::Put {
                key: column_key("inodes", inode_id, "parent_id"),
                value: new_parent_bytes.clone(),
            },
            make_index_delete(
                "inodes",
                "parent_id",
                old_parent_bytes,
                inode_id,
                "move_inode",
            )?,
            make_index_put(
                "inodes",
                "parent_id",
                &new_parent_bytes,
                inode_id,
                "move_inode",
            )?,
        ],
    })
}

pub fn decode_move_inode_payload(bytes: &[u8]) -> Result<(i64, i64, Vec<u8>), ChangelogError> {
    if bytes.len() < MOVE_INODE_PAYLOAD_FIXED_LEN {
        return Err(ChangelogError::Generic(format!(
            "move_inode: payload must be at least {MOVE_INODE_PAYLOAD_FIXED_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&bytes[0..8]);
    let inode_id = i64::from_be_bytes(id_bytes);
    id_bytes.copy_from_slice(&bytes[8..16]);
    let new_parent_id = i64::from_be_bytes(id_bytes);

    let mtime_len = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    if mtime_len > MOVE_INODE_MAX_MTIME_LEN {
        return Err(ChangelogError::Generic(format!(
            "move_inode: declared mtime ciphertext length {mtime_len} exceeds max {MOVE_INODE_MAX_MTIME_LEN}"
        )));
    }
    if bytes.len() != MOVE_INODE_PAYLOAD_FIXED_LEN + mtime_len {
        return Err(ChangelogError::Generic(format!(
            "move_inode: payload length {} != fixed {MOVE_INODE_PAYLOAD_FIXED_LEN} + declared mtime {mtime_len}",
            bytes.len()
        )));
    }
    let mtime_col_bytes = bytes[MOVE_INODE_PAYLOAD_FIXED_LEN..].to_vec();

    Ok((inode_id, new_parent_id, mtime_col_bytes))
}

/// Decoded `add_inode` payload: the non-`id` `inodes` columns.
pub struct AddInodePayload {
    pub parent_id: i64,
    pub author_id: i64,
    pub inode_type: i64,
    pub size_ciphertext: Vec<u8>,
    pub ctime_ciphertext: Vec<u8>,
    pub mtime_ciphertext: Vec<u8>,
    pub name_digest: [u8; 32],
    pub mime_type_digest: [u8; 32],
    pub file_hash: String,
}

fn stored_str_bytes(s: &str, column: &str, op_name: &str) -> Result<Vec<u8>, ChangelogError> {
    value_to_bytes(&serde_json::json!(s)).map_err(|e| {
        ChangelogError::Generic(format!("{op_name}: failed to serialize {column}={s}: {e}"))
    })
}

fn add_inode(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<OpVerifyResult, ChangelogError> {
    let p = decode_add_inode_payload(payload)?;

    if p.inode_type != INODE_FILE && p.inode_type != INODE_FOLDER {
        return Err(ChangelogError::Generic(format!(
            "add_inode: type={} must be 1 (file) or 2 (folder)",
            p.inode_type
        )));
    }

    validate_user_access(entry, OpType::Native, "add_inode", reader)?;

    // `inodes` must be a registered auto-increment table (matches data-driven InsertOp).
    if !read_auto_increment("inodes", "add_inode", reader, ctx)? {
        return Err(ChangelogError::Generic(
            "add_inode: inodes is not an auto-increment table".to_string(),
        ));
    }

    // Server-assigned row id from the next_id counter (strict-freshness pins it).
    let row_id = read_next_id("inodes", "add_inode", reader)?;

    if row_id == p.parent_id {
        return Err(ChangelogError::Generic(format!(
            "add_inode: inode_id={row_id} cannot be its own parent"
        )));
    }

    if p.parent_id != 0 {
        let parent_type_read =
            reader.read(ReadOp::Key(column_key("inodes", p.parent_id, "type")))?;
        let (_, parent_type_value) = parent_type_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "add_inode: parent_id={} is not an existing folder",
                p.parent_id
            ))
        })?;
        let parent_type = decode_i64_column_value(parent_type_value, "add_inode", "inodes.type")?;
        if parent_type != INODE_FOLDER {
            return Err(ChangelogError::Generic(format!(
                "add_inode: parent_id={} has type {parent_type}, expected folder",
                p.parent_id
            )));
        }
    }

    let author_id_bytes = stored_i64_bytes(p.author_id, "author_id", "add_inode")?;
    let parent_id_bytes = stored_i64_bytes(p.parent_id, "parent_id", "add_inode")?;
    let type_bytes = stored_i64_bytes(p.inode_type, "type", "add_inode")?;
    let file_hash_bytes = stored_str_bytes(&p.file_hash, "file_hash", "add_inode")?;

    // Nine non-`id` column Puts in alphabetical column order, then index puts
    // (author_id, parent_id), then the next_id bump. Applied in vector order
    // (MRT/AVL is write-order sensitive).
    let mut writes = vec![
        WriteOp::Put {
            key: column_key("inodes", row_id, "author_id"),
            value: author_id_bytes.clone(),
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "ctime"),
            value: p.ctime_ciphertext,
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "file_hash"),
            value: file_hash_bytes,
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "mime_type"),
            value: p.mime_type_digest.to_vec(),
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "mtime"),
            value: p.mtime_ciphertext,
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "name"),
            value: p.name_digest.to_vec(),
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "parent_id"),
            value: parent_id_bytes.clone(),
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "size"),
            value: p.size_ciphertext,
        },
        WriteOp::Put {
            key: column_key("inodes", row_id, "type"),
            value: type_bytes,
        },
    ];
    writes.push(make_index_put(
        "inodes",
        "author_id",
        &author_id_bytes,
        row_id,
        "add_inode",
    )?);
    writes.push(make_index_put(
        "inodes",
        "parent_id",
        &parent_id_bytes,
        row_id,
        "add_inode",
    )?);
    writes.push(next_id_put(
        "inodes",
        next_id_after(row_id, "inodes", "add_inode")?,
    ));

    Ok(OpVerifyResult {
        write_steps: writes,
    })
}

pub fn decode_add_inode_payload(bytes: &[u8]) -> Result<AddInodePayload, ChangelogError> {
    if bytes.len() < ADD_INODE_PAYLOAD_MIN_LEN {
        return Err(ChangelogError::Generic(format!(
            "add_inode: payload must be at least {ADD_INODE_PAYLOAD_MIN_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let mut cursor = 0usize;
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    let parent_id = i64::from_be_bytes(id_bytes);
    cursor += 8;
    id_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    let author_id = i64::from_be_bytes(id_bytes);
    cursor += 8;
    id_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    let inode_type = i64::from_be_bytes(id_bytes);
    cursor += 8;

    let size_len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    if bytes.len() < cursor + size_len + 4 + 4 + 64 + 4 {
        return Err(ChangelogError::Generic(format!(
            "add_inode: declared size ciphertext length {size_len} overruns payload of {} bytes",
            bytes.len()
        )));
    }
    let size_ciphertext = bytes[cursor..cursor + size_len].to_vec();
    cursor += size_len;

    let ctime_len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    if bytes.len() < cursor + ctime_len + 4 + 64 + 4 {
        return Err(ChangelogError::Generic(format!(
            "add_inode: declared ctime ciphertext length {ctime_len} overruns payload of {} bytes",
            bytes.len()
        )));
    }
    let ctime_ciphertext = bytes[cursor..cursor + ctime_len].to_vec();
    cursor += ctime_len;

    let mtime_len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    if bytes.len() < cursor + mtime_len + 64 + 4 {
        return Err(ChangelogError::Generic(format!(
            "add_inode: declared mtime ciphertext length {mtime_len} overruns payload of {} bytes",
            bytes.len()
        )));
    }
    let mtime_ciphertext = bytes[cursor..cursor + mtime_len].to_vec();
    cursor += mtime_len;

    let mut name_digest = [0u8; 32];
    name_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let mut mime_type_digest = [0u8; 32];
    mime_type_digest.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;

    let file_hash_len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    if bytes.len() != cursor + file_hash_len {
        return Err(ChangelogError::Generic(format!(
            "add_inode: payload length {} != consumed {cursor} + declared file_hash {file_hash_len}",
            bytes.len()
        )));
    }
    let file_hash = String::from_utf8(bytes[cursor..cursor + file_hash_len].to_vec())
        .map_err(|e| ChangelogError::Generic(format!("add_inode: file_hash not utf8: {e}")))?;

    Ok(AddInodePayload {
        parent_id,
        author_id,
        inode_type,
        size_ciphertext,
        ctime_ciphertext,
        mtime_ciphertext,
        name_digest,
        mime_type_digest,
        file_hash,
    })
}

/// Build the delete-set for `row_ids`: every schema column key, plus an index
/// delete for each indexed column (read to recover its stored value).
fn delete_rows_from_schema(
    table: &str,
    row_ids: &[i64],
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<Vec<WriteOp>, ChangelogError> {
    let schema_columns = read_schema_columns(table, op_name, reader, ctx)?;
    let indexed_columns = read_schema_indexes(table, reader, ctx)?;

    let mut delete_ops = Vec::new();
    for row_id in row_ids {
        for col in &schema_columns {
            delete_ops.push(WriteOp::Delete {
                key: column_key(table, *row_id, col),
            });
        }
        for idx_col in &indexed_columns {
            let col_read = reader.read(ReadOp::Key(column_key(table, *row_id, idx_col)))?;
            if let Some((_, val)) = col_read.results.first() {
                delete_ops.push(make_index_delete(table, idx_col, val, *row_id, op_name)?);
            }
        }
    }

    Ok(delete_ops)
}

fn delete_inode_recursive(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<OpVerifyResult, ChangelogError> {
    let inode_id = decode_delete_inode_recursive_payload(payload)?;

    validate_user_access(entry, OpType::Native, "delete_inode_recursive", reader)?;

    let target_read = reader.read(ReadOp::Key(column_key("inodes", inode_id, "parent_id")))?;
    if target_read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "delete_inode_recursive: inodes row_id={inode_id} does not exist"
        )));
    }

    // BFS the subtree via the parent_id index, with depth / node-count caps and
    // cycle detection.
    let mut seen = BTreeSet::from([inode_id]);
    let mut frontier = VecDeque::from([(inode_id, 0usize)]);
    let mut delete_set = Vec::new();

    while let Some((node_id, depth)) = frontier.pop_front() {
        if depth > DELETE_INODE_RECURSIVE_MAX_DEPTH {
            return Err(ChangelogError::Generic(format!(
                "delete_inode_recursive: subtree depth exceeds {DELETE_INODE_RECURSIVE_MAX_DEPTH}"
            )));
        }
        delete_set.push(node_id);
        if delete_set.len() > DELETE_INODE_RECURSIVE_MAX_NODES {
            return Err(ChangelogError::Generic(format!(
                "delete_inode_recursive: subtree contains more than {DELETE_INODE_RECURSIVE_MAX_NODES} nodes"
            )));
        }

        let child_ids = read_indexed_row_ids(
            "inodes",
            "parent_id",
            node_id,
            reader,
            "delete_inode_recursive",
        )?;
        for child_id in child_ids {
            if !seen.insert(child_id) {
                return Err(ChangelogError::Generic(format!(
                    "delete_inode_recursive: cycle or duplicate descendant at inode_id={child_id}"
                )));
            }
            frontier.push_back((child_id, depth + 1));
        }
    }

    let delete_ops =
        delete_rows_from_schema("inodes", &delete_set, "delete_inode_recursive", reader, ctx)?;
    Ok(OpVerifyResult {
        write_steps: delete_ops,
    })
}

pub fn decode_delete_inode_recursive_payload(bytes: &[u8]) -> Result<i64, ChangelogError> {
    if bytes.len() != DELETE_INODE_RECURSIVE_PAYLOAD_LEN {
        return Err(ChangelogError::Generic(format!(
            "delete_inode_recursive: payload must be {DELETE_INODE_RECURSIVE_PAYLOAD_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(bytes);
    Ok(i64::from_be_bytes(id_bytes))
}

// ─── Tree-fs wire codec (shared byte helpers) ────────────────────────────────
// Storage-agnostic payload framing for the tree-fs native ops. The length-
// prefixed byte helpers are the byte-exact inverse pair (write_/read_) shared by
// the SDK (encode) and the in-guest verifier (decode).

fn write_tree_fs_bytes(
    out: &mut Vec<u8>,
    value: &[u8],
    op_name: &str,
    field_name: &str,
) -> Result<(), ChangelogError> {
    if value.len() > TREE_FS_PAYLOAD_MAX_VAR_LEN {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {field_name} length {} exceeds max {TREE_FS_PAYLOAD_MAX_VAR_LEN}",
            value.len()
        )));
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn read_tree_fs_bytes(
    bytes: &[u8],
    cursor: &mut usize,
    op_name: &str,
    field_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let len_bytes = take_tree_fs_bytes(bytes, cursor, 4, op_name, field_name)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len > TREE_FS_PAYLOAD_MAX_VAR_LEN {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {field_name} length {len} exceeds max {TREE_FS_PAYLOAD_MAX_VAR_LEN}"
        )));
    }
    Ok(take_tree_fs_bytes(bytes, cursor, len, op_name, field_name)?.to_vec())
}

fn take_tree_fs_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    op_name: &str,
    field_name: &str,
) -> Result<&'a [u8], ChangelogError> {
    let end = cursor.checked_add(len).ok_or_else(|| {
        ChangelogError::Generic(format!("{op_name}: {field_name} length overflow"))
    })?;
    if end > bytes.len() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {field_name} overruns payload: need {end}, total {}",
            bytes.len()
        )));
    }
    let out = &bytes[*cursor..end];
    *cursor = end;
    Ok(out)
}

// ─── Tree-fs `/dir`+`/info` wire codec ───────────────────────────────────────
// The inode-keyed payloads decoded by the K2 verifiers (and encoded by the K3
// SDK). A path is a sequence of 32-byte inode ids; the create payload carries the
// new child's `Inode` value but never its id — the verifier derives that from the
// accepted entry's `parent_clc`.

/// Encode a tree-fs create payload: `[parent_inode_path][inode_len][Inode bytes]`.
pub fn encode_tree_fs_inode_create_payload(
    parent: &[tree_fs::InodeId],
    inode: &tree_fs::Inode,
) -> Result<Vec<u8>, ChangelogError> {
    tree_fs::encode_container_prefix(parent).map_err(tree_fs_codec_error("tree_fs_create"))?;
    let inode_bytes = inode
        .encode()
        .map_err(tree_fs_codec_error("tree_fs_create"))?;
    let mut out =
        Vec::with_capacity(4 + parent.len() * tree_fs::INODE_ID_LEN + 4 + inode_bytes.len());
    write_tree_fs_inode_path(&mut out, parent);
    write_tree_fs_bytes(&mut out, &inode_bytes, "tree_fs_create", "inode")?;
    Ok(out)
}

/// Encode a tree-fs rename payload: `[inode_path][name_len][name][mtime: i64_be]`.
pub fn encode_tree_fs_inode_rename_payload(
    path: &[tree_fs::InodeId],
    name: &[u8],
    mtime: i64,
) -> Result<Vec<u8>, ChangelogError> {
    tree_fs::encode_record_key(path).map_err(tree_fs_codec_error("tree_fs_rename"))?;
    let mut out = Vec::with_capacity(4 + path.len() * tree_fs::INODE_ID_LEN + 4 + name.len() + 8);
    write_tree_fs_inode_path(&mut out, path);
    write_tree_fs_bytes(&mut out, name, "tree_fs_rename", "name")?;
    out.extend_from_slice(&mtime.to_be_bytes());
    Ok(out)
}

/// Encode a tree-fs move payload:
/// `[source_inode_path][dest_parent_inode_path][mtime: i64_be]`.
pub fn encode_tree_fs_inode_move_payload(
    source: &[tree_fs::InodeId],
    destination_parent: &[tree_fs::InodeId],
    mtime: i64,
) -> Result<Vec<u8>, ChangelogError> {
    tree_fs::encode_record_key(source).map_err(tree_fs_codec_error("tree_fs_move"))?;
    tree_fs::encode_container_prefix(destination_parent)
        .map_err(tree_fs_codec_error("tree_fs_move"))?;
    let mut out = Vec::with_capacity(
        8 + (source.len() + destination_parent.len()) * tree_fs::INODE_ID_LEN + 8,
    );
    write_tree_fs_inode_path(&mut out, source);
    write_tree_fs_inode_path(&mut out, destination_parent);
    out.extend_from_slice(&mtime.to_be_bytes());
    Ok(out)
}

/// Encode a tree-fs delete payload: `[source_inode_path]`.
pub fn encode_tree_fs_inode_delete_payload(
    path: &[tree_fs::InodeId],
) -> Result<Vec<u8>, ChangelogError> {
    tree_fs::encode_record_key(path).map_err(tree_fs_codec_error("tree_fs_delete"))?;
    let mut out = Vec::with_capacity(4 + path.len() * tree_fs::INODE_ID_LEN);
    write_tree_fs_inode_path(&mut out, path);
    Ok(out)
}

pub fn decode_tree_fs_inode_create_payload(
    bytes: &[u8],
) -> Result<TreeFsInodeCreatePayload, ChangelogError> {
    let mut cursor = 0usize;
    let parent = read_tree_fs_inode_path(bytes, &mut cursor, "tree_fs_create")?;
    let inode_bytes = read_tree_fs_bytes(bytes, &mut cursor, "tree_fs_create", "inode")?;
    expect_tree_fs_consumed(bytes, cursor, "tree_fs_create")?;
    let inode =
        tree_fs::Inode::decode(&inode_bytes).map_err(tree_fs_codec_error("tree_fs_create"))?;
    Ok((parent, inode))
}

pub fn decode_tree_fs_inode_rename_payload(
    bytes: &[u8],
) -> Result<TreeFsInodeRenamePayload, ChangelogError> {
    let mut cursor = 0usize;
    let path = read_tree_fs_inode_path(bytes, &mut cursor, "tree_fs_rename")?;
    let name = read_tree_fs_bytes(bytes, &mut cursor, "tree_fs_rename", "name")?;
    let mtime = read_tree_fs_i64(bytes, &mut cursor, "tree_fs_rename", "mtime")?;
    expect_tree_fs_consumed(bytes, cursor, "tree_fs_rename")?;
    Ok((path, name, mtime))
}

pub fn decode_tree_fs_inode_move_payload(
    bytes: &[u8],
) -> Result<TreeFsInodeMovePayload, ChangelogError> {
    let mut cursor = 0usize;
    let source = read_tree_fs_inode_path(bytes, &mut cursor, "tree_fs_move")?;
    let destination_parent = read_tree_fs_inode_path(bytes, &mut cursor, "tree_fs_move")?;
    let mtime = read_tree_fs_i64(bytes, &mut cursor, "tree_fs_move", "mtime")?;
    expect_tree_fs_consumed(bytes, cursor, "tree_fs_move")?;
    Ok((source, destination_parent, mtime))
}

pub fn decode_tree_fs_inode_delete_payload(
    bytes: &[u8],
) -> Result<tree_fs::InodePath, ChangelogError> {
    let mut cursor = 0usize;
    let path = read_tree_fs_inode_path(bytes, &mut cursor, "tree_fs_delete")?;
    expect_tree_fs_consumed(bytes, cursor, "tree_fs_delete")?;
    Ok(path)
}

fn write_tree_fs_inode_path(out: &mut Vec<u8>, path: &[tree_fs::InodeId]) {
    out.extend_from_slice(&(path.len() as u32).to_be_bytes());
    for id in path {
        out.extend_from_slice(id);
    }
}

fn read_tree_fs_inode_path(
    bytes: &[u8],
    cursor: &mut usize,
    op_name: &str,
) -> Result<tree_fs::InodePath, ChangelogError> {
    let len_bytes = take_tree_fs_bytes(bytes, cursor, 4, op_name, "path_len")?;
    let component_count =
        u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if component_count > TREE_FS_PATH_MAX_COMPONENTS {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: path has {component_count} components, max {TREE_FS_PATH_MAX_COMPONENTS}"
        )));
    }
    let raw = take_tree_fs_bytes(
        bytes,
        cursor,
        component_count
            .checked_mul(tree_fs::INODE_ID_LEN)
            .ok_or_else(|| ChangelogError::Generic(format!("{op_name}: path length overflow")))?,
        op_name,
        "path",
    )?;
    let mut path = tree_fs::InodePath::with_capacity(component_count);
    for chunk in raw.chunks_exact(tree_fs::INODE_ID_LEN) {
        path.push(tree_fs::decode_inode_id(chunk).map_err(tree_fs_codec_error(op_name))?);
    }
    Ok(path)
}

fn read_tree_fs_i64(
    bytes: &[u8],
    cursor: &mut usize,
    op_name: &str,
    field_name: &str,
) -> Result<i64, ChangelogError> {
    let raw = take_tree_fs_bytes(bytes, cursor, 8, op_name, field_name)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(raw);
    Ok(i64::from_be_bytes(buf))
}

fn expect_tree_fs_consumed(
    bytes: &[u8],
    cursor: usize,
    op_name: &str,
) -> Result<(), ChangelogError> {
    if cursor != bytes.len() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: unexpected trailing bytes: consumed {cursor}, total {}",
            bytes.len()
        )));
    }
    Ok(())
}

// ─── Tree-fs verifiers (`/dir`+`/info` key model) ────────────────────────────
// The four tree-fs ops on the inode-keyed codec (`crate::tree_fs`). Listing is a
// one-level `/info` prefix scan; move and delete lower to the MRT subtree
// primitives `MovePrefix` / `DeletePrefix` (O(depth), not O(subtree)). The new
// child id is derived from the accepted entry's `parent_clc` — never chosen by
// the payload — so create needs no per-parent counter. MRT/AVL is write-order
// sensitive, so a record relocate emits its `Delete` before the `Put` (§1.1).

fn tree_fs_create(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (parent_path, child_inode) = decode_tree_fs_inode_create_payload(payload)?;
    validate_user_access(entry, OpType::Native, "tree_fs_create", reader)?;

    // Parent must be a directory: root (`[]`) is an implicit directory with no
    // record; a non-root parent must have an existing `Directory` record. Without
    // this, a forged id-chain could plant orphan records under a missing parent.
    if !parent_path.is_empty() {
        let parent =
            read_tree_fs_inode(&parent_path, "tree_fs_create", reader)?.ok_or_else(|| {
                ChangelogError::Generic(format!(
                    "tree_fs_create: parent {parent_path:?} does not exist"
                ))
            })?;
        if inode_kind(&parent, "tree_fs_create")? != tree_fs::NodeKind::Directory {
            return Err(ChangelogError::Generic(format!(
                "tree_fs_create: parent {parent_path:?} is not a directory"
            )));
        }
    }

    // The id is derived from the accepted entry's parent CLC (no counter, no
    // read-modify-write); the payload cannot choose it.
    let child_id = tree_fs::derive_inode_id(entry.parent_clc);
    let mut child_path = parent_path;
    child_path.push(child_id);
    let child_key = tree_fs_inode_record_key(&child_path, "tree_fs_create")?;

    // Target must be vacant (CLC-derived `h` makes a collision a SHA collision,
    // but the absence is still proven).
    if !reader
        .read(ReadOp::Key(child_key.clone()))?
        .results
        .is_empty()
    {
        return Err(ChangelogError::Generic(
            "tree_fs_create: a record already exists for the derived child id".to_string(),
        ));
    }

    let mut write_steps = vec![WriteOp::Put {
        key: child_key,
        value: child_inode
            .encode()
            .map_err(tree_fs_codec_error("tree_fs_create"))?,
    }];
    // Seed a directory's container sentinel so an empty-directory move's
    // `MovePrefix` has a present source prefix (see `tree_fs_dir_sentinel_key`).
    if inode_kind(&child_inode, "tree_fs_create")? == tree_fs::NodeKind::Directory {
        write_steps.push(WriteOp::Put {
            key: tree_fs_dir_sentinel_key(&child_path, "tree_fs_create")?,
            value: TREE_FS_DIR_SENTINEL_VALUE.to_vec(),
        });
    }

    Ok(OpVerifyResult { write_steps })
}

fn tree_fs_rename(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (path, new_name, new_mtime) = decode_tree_fs_inode_rename_payload(payload)?;
    validate_user_access(entry, OpType::Native, "tree_fs_rename", reader)?;

    // Missing target → graceful no-op (no write_steps).
    let Some(mut inode) = read_tree_fs_inode(&path, "tree_fs_rename", reader)? else {
        return Ok(OpVerifyResult {
            write_steps: vec![],
        });
    };
    inode.name = new_name;
    inode.mtime = new_mtime;

    Ok(OpVerifyResult {
        write_steps: vec![tree_fs_put_inode(&path, &inode, "tree_fs_rename")?],
    })
}

fn tree_fs_move(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let (source_path, destination_parent_path, new_mtime) =
        decode_tree_fs_inode_move_payload(payload)?;
    validate_user_access(entry, OpType::Native, "tree_fs_move", reader)?;

    // Source ≠ root (can't move `/`).
    let Some((node_id, source_parent_path)) = source_path.split_last() else {
        return Err(ChangelogError::Generic(
            "tree_fs_move: cannot move the root".to_string(),
        ));
    };

    // Missing source → graceful no-op.
    let Some(mut inode) = read_tree_fs_inode(&source_path, "tree_fs_move", reader)? else {
        return Ok(OpVerifyResult {
            write_steps: vec![],
        });
    };
    let source_is_dir = inode_kind(&inode, "tree_fs_move")? == tree_fs::NodeKind::Directory;

    // No cycle: the destination container must not lie inside the source subtree.
    // `CONTAINER(N) = CONTAINER(A) ‖ /dir ‖ h_N`, and `/dir`-tagged id segments are
    // fixed-width, so a byte prefix is exactly a path prefix.
    let source_container = tree_fs::encode_container_prefix(&source_path)
        .map_err(tree_fs_codec_error("tree_fs_move"))?;
    let destination_parent_container = tree_fs::encode_container_prefix(&destination_parent_path)
        .map_err(tree_fs_codec_error("tree_fs_move"))?;
    if destination_parent_container.starts_with(&source_container) {
        return Err(ChangelogError::Generic(format!(
            "tree_fs_move: destination {destination_parent_path:?} is inside source {source_path:?}"
        )));
    }

    // Same-parent move is a no-op: ids are stable, so the source and destination
    // record keys are identical. Short-circuit BEFORE the conflict check, which
    // would otherwise reject the node against itself.
    if source_parent_path == destination_parent_path.as_slice() {
        return Ok(OpVerifyResult {
            write_steps: vec![],
        });
    }

    // Destination parent must be a directory: root (`[]`) implicit; else existing
    // `Directory` record.
    if !destination_parent_path.is_empty() {
        let destination_parent =
            read_tree_fs_inode(&destination_parent_path, "tree_fs_move", reader)?.ok_or_else(
                || {
                    ChangelogError::Generic(format!(
                    "tree_fs_move: destination parent {destination_parent_path:?} does not exist"
                ))
                },
            )?;
        if inode_kind(&destination_parent, "tree_fs_move")? != tree_fs::NodeKind::Directory {
            return Err(ChangelogError::Generic(format!(
                "tree_fs_move: destination parent {destination_parent_path:?} is not a directory"
            )));
        }
    }

    // No destination conflict (cross-parent), per DESIGN §4. The target record key
    // must be vacant, and — for a directory — so must the target container. merk's
    // `MovePrefix` is NOT a verifier-level conflict check: its `splice_at` uses
    // OVERWRITE semantics when the destination prefix is occupied, so a non-empty
    // `CONTAINER(B) ‖ /dir ‖ h_N` would be silently clobbered by the moved subtree.
    // Both are proven-absent reads; the container scan is a cheap O(depth)
    // non-inclusion proof precisely because it is required empty.
    let mut destination_path = destination_parent_path;
    destination_path.push(*node_id);
    let destination_key = tree_fs_inode_record_key(&destination_path, "tree_fs_move")?;
    if !reader
        .read(ReadOp::Key(destination_key))?
        .results
        .is_empty()
    {
        return Err(ChangelogError::Generic(
            "tree_fs_move: destination already holds a record for this id".to_string(),
        ));
    }
    let destination_container = tree_fs::encode_container_prefix(&destination_path)
        .map_err(tree_fs_codec_error("tree_fs_move"))?;
    if source_is_dir
        && !reader
            .read(ReadOp::Prefix(destination_container.clone()))?
            .results
            .is_empty()
    {
        return Err(ChangelogError::Generic(
            "tree_fs_move: destination container already holds a subtree for this id".to_string(),
        ));
    }

    // Lower to the MRT primitives: relocate the subtree container (directories
    // only) with one `MovePrefix`, then relocate the record (Delete old, Put new
    // with an `mtime` bump). Total O(depth) — no per-descendant writes.
    //
    // merk's `MovePrefix` errors on an *absent* source prefix (unlike the
    // tolerant `DeletePrefix`). A directory's container would be empty until it
    // gains a child, so `tree_fs_create` seeds a per-directory container sentinel
    // (`tree_fs_dir_sentinel_key`) keeping every directory's container non-empty.
    // The source prefix is therefore always present here — the verifier needs no
    // O(subtree) emptiness read, and the move stays O(depth).
    let source_key = tree_fs_inode_record_key(&source_path, "tree_fs_move")?;
    inode.mtime = new_mtime;
    let mut writes = Vec::with_capacity(3);
    if source_is_dir {
        writes.push(WriteOp::MovePrefix {
            from: source_container,
            to: destination_container,
        });
    }
    writes.push(WriteOp::Delete { key: source_key });
    writes.push(tree_fs_put_inode(
        &destination_path,
        &inode,
        "tree_fs_move",
    )?);

    Ok(OpVerifyResult {
        write_steps: writes,
    })
}

fn tree_fs_delete(
    entry: &ChangelogEntry,
    payload: &[u8],
    reader: &mut dyn OpReader,
) -> Result<OpVerifyResult, ChangelogError> {
    let source_path = decode_tree_fs_inode_delete_payload(payload)?;
    validate_user_access(entry, OpType::Native, "tree_fs_delete", reader)?;

    // Source ≠ root.
    if source_path.is_empty() {
        return Err(ChangelogError::Generic(
            "tree_fs_delete: cannot delete the root".to_string(),
        ));
    }

    // Missing source → graceful no-op.
    let Some(inode) = read_tree_fs_inode(&source_path, "tree_fs_delete", reader)? else {
        return Ok(OpVerifyResult {
            write_steps: vec![],
        });
    };
    let source_is_dir = inode_kind(&inode, "tree_fs_delete")? == tree_fs::NodeKind::Directory;

    // Lower to the MRT primitives: delete the subtree container (directories only)
    // with one `DeletePrefix`, then delete the record. Total O(depth).
    let record_key = tree_fs_inode_record_key(&source_path, "tree_fs_delete")?;
    let mut writes = Vec::with_capacity(2);
    if source_is_dir {
        let container = tree_fs::encode_container_prefix(&source_path)
            .map_err(tree_fs_codec_error("tree_fs_delete"))?;
        writes.push(WriteOp::DeletePrefix { prefix: container });
    }
    writes.push(WriteOp::Delete { key: record_key });

    Ok(OpVerifyResult {
        write_steps: writes,
    })
}

/// A node's `kind`, mapping the inode codec error into a verifier error.
fn inode_kind(inode: &tree_fs::Inode, op_name: &str) -> Result<tree_fs::NodeKind, ChangelogError> {
    inode.kind().map_err(tree_fs_codec_error(op_name))
}

/// Read and decode the [`tree_fs::Inode`] at `path`, or `None` if the record key
/// is absent (a proven non-inclusion).
fn read_tree_fs_inode(
    path: &[tree_fs::InodeId],
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<Option<tree_fs::Inode>, ChangelogError> {
    let key = tree_fs_inode_record_key(path, op_name)?;
    let read = reader.read(ReadOp::Key(key))?;
    let Some((_, bytes)) = read.results.first() else {
        return Ok(None);
    };
    tree_fs::Inode::decode(bytes)
        .map(Some)
        .map_err(tree_fs_codec_error(op_name))
}

fn tree_fs_put_inode(
    path: &[tree_fs::InodeId],
    inode: &tree_fs::Inode,
    op_name: &str,
) -> Result<WriteOp, ChangelogError> {
    Ok(WriteOp::Put {
        key: tree_fs_inode_record_key(path, op_name)?,
        value: inode.encode().map_err(tree_fs_codec_error(op_name))?,
    })
}

fn tree_fs_inode_record_key(
    path: &[tree_fs::InodeId],
    op_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    tree_fs::encode_record_key(path).map_err(tree_fs_codec_error(op_name))
}

fn tree_fs_codec_error(op_name: &str) -> impl FnOnce(tree_fs::CodecError) -> ChangelogError + '_ {
    move |err| ChangelogError::Generic(format!("{op_name}: {err}"))
}

/// Fixed tag for a directory's container sentinel key, byte-distinct from
/// `/info` and `/dir` so the sentinel is never a child record or sub-container
/// — and is invisible to a one-level `CONTAINER ‖ /info` listing.
const TREE_FS_DIR_SENTINEL_TAG: &[u8; 4] = b"/cnt";

/// The single stored byte for a directory's container sentinel value.
const TREE_FS_DIR_SENTINEL_VALUE: &[u8; 1] = b"1";

/// Build the container-sentinel key for a directory at `dir_path`:
/// `CONTAINER(dir_path) ‖ /cnt`.
///
/// A directory's `/dir` container holds no keys until it gains a child, but
/// merk's `MovePrefix` errors on an *absent* source prefix (unlike the tolerant
/// `DeletePrefix`) — so an empty directory could not be moved. Seeding this one
/// sentinel key when a directory is created keeps its container non-empty, so an
/// empty-directory move's `MovePrefix` always has a present source. The sentinel
/// rides the container through `MovePrefix` and is removed with it by
/// `DeletePrefix`; files have no container and need none.
fn tree_fs_dir_sentinel_key(
    dir_path: &[tree_fs::InodeId],
    op_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let mut key =
        tree_fs::encode_container_prefix(dir_path).map_err(tree_fs_codec_error(op_name))?;
    key.extend_from_slice(TREE_FS_DIR_SENTINEL_TAG);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{KvData, LogMessage};
    use crate::ops::{dispatch_extract_and_validate, VerifierReader};
    use crate::ProvenRead;

    fn stored_i64(value: i64) -> Vec<u8> {
        encrypted_spaces_storage_encoding::stored_value::value_to_bytes(&serde_json::json!(value))
            .unwrap()
    }

    fn native_update_message_entry(
        uid: u32,
        message_id: i64,
        content_digest: &[u8; 32],
    ) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Native,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![
                    KvData {
                        key: native_marker_key(),
                        value: encode_native_header(UPDATE_MESSAGE_KIND, UPDATE_MESSAGE_VERSION),
                    },
                    KvData {
                        key: native_payload_key(),
                        value: encode_update_message_payload(message_id, content_digest),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    fn key_read(key: Vec<u8>, value: Vec<u8>) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, value)],
        }
    }

    #[test]
    fn native_ops_update_message_owner_writes_content_digest() {
        let uid = 7;
        let message_id = 42;
        let digest = [0xAB; 32];
        let entry = native_update_message_entry(uid, message_id, &digest);
        let user_status_key = column_key("_users", uid as i64, "status");
        let owner_key = column_key("messages", message_id, "user_id");
        let reads = vec![
            key_read(user_status_key, stored_i64(1)),
            key_read(owner_key, stored_i64(uid as i64)),
        ];
        let ctx = OpContext::for_change_id(1);

        let mut reader = VerifierReader::new(&reads);
        let result = dispatch_extract_and_validate(&entry, &mut reader, &ctx).unwrap();
        reader.assert_all_consumed().unwrap();

        assert_eq!(
            result.write_steps,
            vec![WriteOp::Put {
                key: column_key("messages", message_id, "content"),
                value: digest.to_vec(),
            }]
        );
    }

    fn native_rename_inode_entry(
        uid: u32,
        inode_id: i64,
        name_digest: &[u8; 32],
        mtime: &[u8],
    ) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Native,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![
                    KvData {
                        key: native_marker_key(),
                        value: encode_native_header(RENAME_INODE_KIND, RENAME_INODE_VERSION),
                    },
                    KvData {
                        key: native_payload_key(),
                        value: encode_rename_inode_payload(inode_id, name_digest, mtime),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn native_ops_rename_inode_writes_mtime_then_name() {
        let uid = 7;
        let inode_id = 42;
        let name_digest = [0xCD; 32];
        let mtime = vec![1, 2, 3, 4];
        let entry = native_rename_inode_entry(uid, inode_id, &name_digest, &mtime);
        let reads = vec![
            key_read(column_key("_users", uid as i64, "status"), stored_i64(1)),
            key_read(column_key("inodes", inode_id, "type"), stored_i64(1)),
        ];
        let ctx = OpContext::for_change_id(1);

        let mut reader = VerifierReader::new(&reads);
        let result = dispatch_extract_and_validate(&entry, &mut reader, &ctx).unwrap();
        reader.assert_all_consumed().unwrap();

        assert_eq!(
            result.write_steps,
            vec![
                WriteOp::Put {
                    key: column_key("inodes", inode_id, "mtime"),
                    value: mtime.clone(),
                },
                WriteOp::Put {
                    key: column_key("inodes", inode_id, "name"),
                    value: name_digest.to_vec(),
                },
            ]
        );
    }

    fn native_move_inode_entry(
        uid: u32,
        inode_id: i64,
        new_parent_id: i64,
        mtime: &[u8],
    ) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Native,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![
                    KvData {
                        key: native_marker_key(),
                        value: encode_native_header(MOVE_INODE_KIND, MOVE_INODE_VERSION),
                    },
                    KvData {
                        key: native_payload_key(),
                        value: encode_move_inode_payload(inode_id, new_parent_id, mtime),
                    },
                ],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn native_ops_move_inode_to_root_updates_parent_and_index() {
        let uid = 7;
        let inode_id = 42;
        let old_parent_id = 5;
        let new_parent_id = 0; // root → no parent-type read
        let mtime = vec![9, 9, 9, 9];
        let entry = native_move_inode_entry(uid, inode_id, new_parent_id, &mtime);
        let reads = vec![
            key_read(column_key("_users", uid as i64, "status"), stored_i64(1)),
            key_read(
                column_key("inodes", inode_id, "parent_id"),
                stored_i64(old_parent_id),
            ),
        ];
        let ctx = OpContext::for_change_id(1);

        let mut reader = VerifierReader::new(&reads);
        let result = dispatch_extract_and_validate(&entry, &mut reader, &ctx).unwrap();
        reader.assert_all_consumed().unwrap();

        let new_parent_bytes = stored_i64(new_parent_id);
        assert_eq!(
            result.write_steps,
            vec![
                WriteOp::Put {
                    key: column_key("inodes", inode_id, "mtime"),
                    value: mtime.clone(),
                },
                WriteOp::Put {
                    key: column_key("inodes", inode_id, "parent_id"),
                    value: new_parent_bytes.clone(),
                },
                make_index_delete(
                    "inodes",
                    "parent_id",
                    &stored_i64(old_parent_id),
                    inode_id,
                    "move_inode",
                )
                .unwrap(),
                make_index_put(
                    "inodes",
                    "parent_id",
                    &new_parent_bytes,
                    inode_id,
                    "move_inode"
                )
                .unwrap(),
            ]
        );
    }

    #[test]
    fn add_inode_payload_round_trips_and_rejects_truncation() {
        let p = AddInodePayload {
            parent_id: 3,
            author_id: 7,
            inode_type: 1,
            size_ciphertext: vec![1, 2, 3],
            ctime_ciphertext: vec![4, 5],
            mtime_ciphertext: vec![6, 7, 8, 9],
            name_digest: [0xAA; 32],
            mime_type_digest: [0xBB; 32],
            file_hash: "abc123".to_string(),
        };
        let bytes = encode_add_inode_payload(
            p.parent_id,
            p.author_id,
            p.inode_type,
            &p.size_ciphertext,
            &p.ctime_ciphertext,
            &p.mtime_ciphertext,
            &p.name_digest,
            &p.mime_type_digest,
            &p.file_hash,
        );
        let d = decode_add_inode_payload(&bytes).unwrap();
        assert_eq!(d.parent_id, p.parent_id);
        assert_eq!(d.author_id, p.author_id);
        assert_eq!(d.inode_type, p.inode_type);
        assert_eq!(d.size_ciphertext, p.size_ciphertext);
        assert_eq!(d.ctime_ciphertext, p.ctime_ciphertext);
        assert_eq!(d.mtime_ciphertext, p.mtime_ciphertext);
        assert_eq!(d.name_digest, p.name_digest);
        assert_eq!(d.mime_type_digest, p.mime_type_digest);
        assert_eq!(d.file_hash, p.file_hash);
        // Short payloads and trailing-byte framing are hard errors.
        assert!(decode_add_inode_payload(&bytes[..ADD_INODE_PAYLOAD_MIN_LEN - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_add_inode_payload(&trailing).is_err());
    }

    #[test]
    fn delete_inode_recursive_payload_round_trips_and_rejects_bad_length() {
        let bytes = encode_delete_inode_recursive_payload(42);
        assert_eq!(decode_delete_inode_recursive_payload(&bytes).unwrap(), 42);
        assert!(decode_delete_inode_recursive_payload(&bytes[..7]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_delete_inode_recursive_payload(&long).is_err());
    }

    // ─── Tree-fs verifier tests (`/dir`+`/info` key model) ───────────────────
    // Shape + precondition tests: call the verifier fn directly and inspect the
    // returned `write_steps` against a `VerifierReader` seeded with the exact
    // reads the verifier issues. No proving here (see the roundtrip module).

    fn tree_fs_id(byte: u8) -> tree_fs::InodeId {
        [byte; tree_fs::INODE_ID_LEN]
    }

    fn tree_fs_inode(kind: tree_fs::NodeKind, name: &[u8]) -> tree_fs::Inode {
        tree_fs::Inode {
            version: tree_fs::INODE_VERSION,
            flags: kind.flags(),
            author_uid: 7,
            size: 0,
            ctime: 100,
            mtime: 100,
            content_hash: [0u8; tree_fs::CONTENT_HASH_LEN],
            name: name.to_vec(),
        }
    }

    /// A minimal native entry. The shape tests call the verifier fns directly with
    /// a pre-encoded payload, so only `uid` (ACL) and `parent_clc` (create's id
    /// derivation) are read.
    fn tree_fs_entry(uid: u32, parent_clc: [u8; 32]) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Native,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![],
            },
            sig_ref: 0,
            parent_clc,
            signature: vec![],
        }
    }

    fn tree_fs_status_read(uid: u32) -> ProvenRead {
        key_read(column_key("_users", uid as i64, "status"), stored_i64(1))
    }

    fn absent_read(key: Vec<u8>) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }
    }

    fn record_read(path: &[tree_fs::InodeId], inode: &tree_fs::Inode) -> ProvenRead {
        key_read(
            tree_fs::encode_record_key(path).unwrap(),
            inode.encode().unwrap(),
        )
    }

    fn empty_prefix_read(prefix: Vec<u8>) -> ProvenRead {
        ProvenRead {
            op: ReadOp::Prefix(prefix),
            results: vec![],
        }
    }

    #[test]
    fn tree_fs_move_cross_parent_emits_one_moveprefix() {
        let uid = 7;
        // 3-level tree: root → id1 → id2 (a level-2 directory). Move id2 to root.
        let (id1, id2) = (tree_fs_id(1), tree_fs_id(2));
        let source = vec![id1, id2];
        let dest_parent: Vec<tree_fs::InodeId> = vec![];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 200).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let source_dir = tree_fs_inode(tree_fs::NodeKind::Directory, b"docs");
        let dest_path = vec![id2];
        // For a directory move the verifier proves both the destination record key
        // and the destination container are vacant.
        let reads = vec![
            tree_fs_status_read(uid),
            record_read(&source, &source_dir),
            absent_read(tree_fs::encode_record_key(&dest_path).unwrap()),
            empty_prefix_read(tree_fs::encode_container_prefix(&dest_path).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_move(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        let mut moved = source_dir.clone();
        moved.mtime = 200;
        assert_eq!(
            result.write_steps,
            vec![
                WriteOp::MovePrefix {
                    from: tree_fs::encode_container_prefix(&source).unwrap(),
                    to: tree_fs::encode_container_prefix(&dest_path).unwrap(),
                },
                WriteOp::Delete {
                    key: tree_fs::encode_record_key(&source).unwrap(),
                },
                WriteOp::Put {
                    key: tree_fs::encode_record_key(&dest_path).unwrap(),
                    value: moved.encode().unwrap(),
                },
            ]
        );
        // Exactly one prefix relocate; zero per-descendant Put/Delete.
        let move_prefixes = result
            .write_steps
            .iter()
            .filter(|w| matches!(w, WriteOp::MovePrefix { .. }))
            .count();
        assert_eq!(move_prefixes, 1);
        assert_eq!(result.write_steps.len(), 3);
    }

    #[test]
    fn tree_fs_move_rejects_occupied_destination_container() {
        // The destination *record* key is vacant, but the destination *container*
        // already holds a child subtree. merk's `MovePrefix` would silently
        // overwrite it, so the verifier must reject (DESIGN §4).
        let uid = 7;
        let (id1, id2, id3) = (tree_fs_id(1), tree_fs_id(2), tree_fs_id(3));
        let source = vec![id1, id2];
        let dest_parent: Vec<tree_fs::InodeId> = vec![];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 200).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let source_dir = tree_fs_inode(tree_fs::NodeKind::Directory, b"docs");
        let dest_path = vec![id2];
        // A pre-existing grandchild record under the destination container.
        let occupant = tree_fs_inode(tree_fs::NodeKind::File, b"occupant.txt");
        let reads = vec![
            tree_fs_status_read(uid),
            record_read(&source, &source_dir),
            absent_read(tree_fs::encode_record_key(&dest_path).unwrap()),
            ProvenRead {
                op: ReadOp::Prefix(tree_fs::encode_container_prefix(&dest_path).unwrap()),
                results: vec![(
                    tree_fs::encode_record_key(&[id2, id3]).unwrap(),
                    occupant.encode().unwrap(),
                )],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = tree_fs_move(&entry, &payload, &mut reader).unwrap_err();
        reader.assert_all_consumed().unwrap();
        assert!(
            format!("{err}").contains("destination container already holds"),
            "{err}"
        );
    }

    #[test]
    fn tree_fs_move_file_cross_parent_no_container_read() {
        // A file has no container, so a file move emits no `MovePrefix` and skips
        // the destination-container probe (only the record-key vacancy is read).
        let uid = 7;
        let (id1, id2) = (tree_fs_id(1), tree_fs_id(2));
        let source = vec![id1, id2];
        let dest_parent: Vec<tree_fs::InodeId> = vec![];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 200).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let source_file = tree_fs_inode(tree_fs::NodeKind::File, b"a.txt");
        let dest_path = vec![id2];
        // No container prefix read seeded — assert_all_consumed catches a stray one.
        let reads = vec![
            tree_fs_status_read(uid),
            record_read(&source, &source_file),
            absent_read(tree_fs::encode_record_key(&dest_path).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_move(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        let mut moved = source_file.clone();
        moved.mtime = 200;
        assert_eq!(
            result.write_steps,
            vec![
                WriteOp::Delete {
                    key: tree_fs::encode_record_key(&source).unwrap(),
                },
                WriteOp::Put {
                    key: tree_fs::encode_record_key(&dest_path).unwrap(),
                    value: moved.encode().unwrap(),
                },
            ]
        );
        assert!(!result
            .write_steps
            .iter()
            .any(|w| matches!(w, WriteOp::MovePrefix { .. })));
    }

    #[test]
    fn tree_fs_delete_dir_emits_one_deleteprefix() {
        let uid = 7;
        let (id1, id2) = (tree_fs_id(1), tree_fs_id(2));
        let source = vec![id1, id2];
        let payload = encode_tree_fs_inode_delete_payload(&source).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let dir = tree_fs_inode(tree_fs::NodeKind::Directory, b"docs");
        let reads = vec![tree_fs_status_read(uid), record_read(&source, &dir)];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_delete(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        assert_eq!(
            result.write_steps,
            vec![
                WriteOp::DeletePrefix {
                    prefix: tree_fs::encode_container_prefix(&source).unwrap(),
                },
                WriteOp::Delete {
                    key: tree_fs::encode_record_key(&source).unwrap(),
                },
            ]
        );
        let delete_prefixes = result
            .write_steps
            .iter()
            .filter(|w| matches!(w, WriteOp::DeletePrefix { .. }))
            .count();
        assert_eq!(delete_prefixes, 1);
        assert_eq!(result.write_steps.len(), 2);
    }

    #[test]
    fn tree_fs_delete_file_emits_only_record_delete() {
        // A file has no `/dir` container, so delete emits the record `Delete` only.
        let uid = 7;
        let source = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_delete_payload(&source).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let file = tree_fs_inode(tree_fs::NodeKind::File, b"a.txt");
        let reads = vec![tree_fs_status_read(uid), record_read(&source, &file)];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_delete(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        assert_eq!(
            result.write_steps,
            vec![WriteOp::Delete {
                key: tree_fs::encode_record_key(&source).unwrap(),
            }]
        );
    }

    #[test]
    fn tree_fs_create_rejects_absent_parent() {
        let uid = 7;
        let parent = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_create_payload(
            &parent,
            &tree_fs_inode(tree_fs::NodeKind::File, b"a.txt"),
        )
        .unwrap();
        let entry = tree_fs_entry(uid, [9u8; 32]);

        let reads = vec![
            tree_fs_status_read(uid),
            absent_read(tree_fs::encode_record_key(&parent).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let err = tree_fs_create(&entry, &payload, &mut reader).unwrap_err();
        reader.assert_all_consumed().unwrap();
        assert!(format!("{err}").contains("does not exist"), "{err}");
    }

    #[test]
    fn tree_fs_create_rejects_file_parent() {
        let uid = 7;
        let parent = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_create_payload(
            &parent,
            &tree_fs_inode(tree_fs::NodeKind::File, b"a.txt"),
        )
        .unwrap();
        let entry = tree_fs_entry(uid, [9u8; 32]);

        let parent_file = tree_fs_inode(tree_fs::NodeKind::File, b"not-a-dir");
        let reads = vec![tree_fs_status_read(uid), record_read(&parent, &parent_file)];
        let mut reader = VerifierReader::new(&reads);
        let err = tree_fs_create(&entry, &payload, &mut reader).unwrap_err();
        reader.assert_all_consumed().unwrap();
        assert!(format!("{err}").contains("not a directory"), "{err}");
    }

    #[test]
    fn tree_fs_create_under_root_emits_one_put_at_derived_id() {
        let uid = 7;
        let parent_clc = [0x5Au8; 32];
        let inode = tree_fs_inode(tree_fs::NodeKind::File, b"a.txt");
        let payload = encode_tree_fs_inode_create_payload(&[], &inode).unwrap();
        let entry = tree_fs_entry(uid, parent_clc);

        let child_id = tree_fs::derive_inode_id(parent_clc);
        let child_path = vec![child_id];
        // Root parent ([]) is implicit — only status + the vacancy probe are read.
        let reads = vec![
            tree_fs_status_read(uid),
            absent_read(tree_fs::encode_record_key(&child_path).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_create(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        assert_eq!(
            result.write_steps,
            vec![WriteOp::Put {
                key: tree_fs::encode_record_key(&child_path).unwrap(),
                value: inode.encode().unwrap(),
            }]
        );
    }

    #[test]
    fn tree_fs_rename_missing_target_noop() {
        let uid = 7;
        let path = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_rename_payload(&path, b"new", 300).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let reads = vec![
            tree_fs_status_read(uid),
            absent_read(tree_fs::encode_record_key(&path).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_rename(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();
        assert!(result.write_steps.is_empty());
    }

    #[test]
    fn tree_fs_rename_rewrites_record() {
        let uid = 7;
        let path = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_rename_payload(&path, b"renamed", 300).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let before = tree_fs_inode(tree_fs::NodeKind::File, b"old");
        let reads = vec![tree_fs_status_read(uid), record_read(&path, &before)];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_rename(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();

        let mut after = before.clone();
        after.name = b"renamed".to_vec();
        after.mtime = 300;
        assert_eq!(
            result.write_steps,
            vec![WriteOp::Put {
                key: tree_fs::encode_record_key(&path).unwrap(),
                value: after.encode().unwrap(),
            }]
        );
    }

    #[test]
    fn tree_fs_move_missing_target_noop() {
        let uid = 7;
        let source = vec![tree_fs_id(1), tree_fs_id(2)];
        let dest_parent: Vec<tree_fs::InodeId> = vec![];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 0).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let reads = vec![
            tree_fs_status_read(uid),
            absent_read(tree_fs::encode_record_key(&source).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_move(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();
        assert!(result.write_steps.is_empty());
    }

    #[test]
    fn tree_fs_delete_missing_target_noop() {
        let uid = 7;
        let source = vec![tree_fs_id(1)];
        let payload = encode_tree_fs_inode_delete_payload(&source).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let reads = vec![
            tree_fs_status_read(uid),
            absent_read(tree_fs::encode_record_key(&source).unwrap()),
        ];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_delete(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();
        assert!(result.write_steps.is_empty());
    }

    #[test]
    fn tree_fs_move_same_parent_noop() {
        let uid = 7;
        // Same parent id1: source [id1, id2] moved under [id1] is a no-op.
        let (id1, id2) = (tree_fs_id(1), tree_fs_id(2));
        let source = vec![id1, id2];
        let dest_parent = vec![id1];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 200).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let dir = tree_fs_inode(tree_fs::NodeKind::Directory, b"docs");
        // Short-circuits before any destination read.
        let reads = vec![tree_fs_status_read(uid), record_read(&source, &dir)];
        let mut reader = VerifierReader::new(&reads);
        let result = tree_fs_move(&entry, &payload, &mut reader).unwrap();
        reader.assert_all_consumed().unwrap();
        assert!(result.write_steps.is_empty());
    }

    #[test]
    fn tree_fs_move_rejects_cycle() {
        let uid = 7;
        // Move id1 (under root) into its own child id1/id2 — a cycle.
        let (id1, id2) = (tree_fs_id(1), tree_fs_id(2));
        let source = vec![id1];
        let dest_parent = vec![id1, id2];
        let payload = encode_tree_fs_inode_move_payload(&source, &dest_parent, 0).unwrap();
        let entry = tree_fs_entry(uid, [0u8; 32]);

        let dir = tree_fs_inode(tree_fs::NodeKind::Directory, b"docs");
        let reads = vec![tree_fs_status_read(uid), record_read(&source, &dir)];
        let mut reader = VerifierReader::new(&reads);
        let err = tree_fs_move(&entry, &payload, &mut reader).unwrap_err();
        reader.assert_all_consumed().unwrap();
        assert!(format!("{err}").contains("inside source"), "{err}");
    }

    #[test]
    fn tree_fs_move_rejects_root_source() {
        let uid = 7;
        // The encoder rejects an empty source path, so hand-build the payload a
        // malicious prover would: empty source, dest parent [id1], mtime 0.
        let mut payload = Vec::new();
        write_tree_fs_inode_path(&mut payload, &[]);
        write_tree_fs_inode_path(&mut payload, &[tree_fs_id(1)]);
        payload.extend_from_slice(&0i64.to_be_bytes());
        let entry = tree_fs_entry(uid, [0u8; 32]);

        // Root-source is rejected after the ACL status read, before any record read.
        let reads = vec![tree_fs_status_read(uid)];
        let mut reader = VerifierReader::new(&reads);
        let err = tree_fs_move(&entry, &payload, &mut reader).unwrap_err();
        reader.assert_all_consumed().unwrap();
        assert!(format!("{err}").contains("cannot move the root"), "{err}");
    }
}

// ─── K0 spike: MRT prefix-op proof tests ─────────────────────────────────────
// The key model lowers tree-fs move/delete to merk `MovePrefix`/`DeletePrefix`
// (O(depth), not O(subtree)). These tests prove the load-bearing assumption that
// such a step proves correctly on MRT: it records into a witness, *verifies that
// witness against the start DC*, and *replays* it through the same
// `TraceReplayer` merk runs in-guest under proof — reproducing the post-op data
// commitment of a reference tree that applied the relocate/delete directly.
//
// Pure merk (no zkVM guest), exercising the exact `TraceRecorder`/`TraceReplayer`
// seam the prover (`ffproof/src/prover.rs`) and storage write path
// (`backend/src/merk_storage/proofs.rs`) use. MRT-only — the prefix ops are an
// MRT capability — so the module is gated on the `mrt` feature.
#[cfg(all(test, feature = "mrt"))]
mod mrt_prefix_proof_tests {
    use ffproof_tracer_shared::{TraceInterface, TraceRecorder, TraceReplayer, Tree, WriteOp};

    /// A small tree with a three-key subtree under prefix `b"user:"` plus two
    /// siblings (`b"sys:log"`, `b"zzz"`) that any prefix op must leave untouched.
    fn seed_tree() -> Tree {
        let tree = Tree::new();
        for (key, value) in [
            (b"sys:log".as_slice(), b"3".as_slice()),
            (b"user:alex".as_slice(), b"2".as_slice()),
            (b"user:alice".as_slice(), b"1".as_slice()),
            (b"user:bob".as_slice(), b"4".as_slice()),
            (b"zzz".as_slice(), b"5".as_slice()),
        ] {
            tree.put(key, value).expect("seed put");
        }
        tree
    }

    /// Record `writes` against a snapshot of `tree`, verify the witness binds to
    /// the start DC, and replay it. Returns the replayer's recomputed post-op DC.
    /// Panics (failing the test) if the witness fails to verify or the in-guest
    /// replayer cannot apply the prefix op — exactly the K0 STOP-AND-REPORT signal.
    fn prove_writes(tree: &Tree, writes: &[WriteOp]) -> [u8; 32] {
        let snapshot = tree.checkpoint();
        let start_dc = snapshot.root_hash();

        let mut recorder = TraceRecorder::new(&snapshot);
        recorder.apply(writes).expect("recorder applies prefix op");
        let trace_bytes = recorder.finalize_trace().expect("finalize trace witness");

        let mut replayer = TraceReplayer::new_verified(&trace_bytes, start_dc)
            .expect("trace witness verifies against the start DC");
        replayer.apply(writes).expect("replayer applies prefix op");
        replayer
            .root_hash()
            .expect("replayer recomputes the post-op DC")
    }

    #[test]
    fn move_prefix_proves() {
        let tree = seed_tree();
        let writes = vec![WriteOp::MovePrefix {
            from: b"user:".to_vec(),
            to: b"acct:".to_vec(),
        }];

        let proven_dc = prove_writes(&tree, &writes);

        // Reference: apply the same relocate directly to an identical tree.
        let reference = seed_tree();
        reference
            .apply_write_ops(&writes)
            .expect("reference applies MovePrefix directly");

        assert_eq!(
            proven_dc,
            reference.root_hash(),
            "proven MovePrefix DC must equal the directly-relocated reference DC"
        );
        // The relocate is what we expect: subtree moved, siblings intact.
        assert_eq!(reference.get(b"acct:alex"), Some(b"2".to_vec()));
        assert_eq!(reference.get(b"user:alex"), None);
        assert_eq!(reference.get(b"sys:log"), Some(b"3".to_vec()));
        assert_eq!(reference.get(b"zzz"), Some(b"5".to_vec()));
    }

    #[test]
    fn delete_prefix_proves() {
        let tree = seed_tree();
        let writes = vec![WriteOp::DeletePrefix {
            prefix: b"user:".to_vec(),
        }];

        let proven_dc = prove_writes(&tree, &writes);

        // Reference: apply the same prefix delete directly to an identical tree.
        let reference = seed_tree();
        reference
            .apply_write_ops(&writes)
            .expect("reference applies DeletePrefix directly");

        assert_eq!(
            proven_dc,
            reference.root_hash(),
            "proven DeletePrefix DC must equal the directly-deleted reference DC"
        );
        // The whole `user:` subtree is gone; siblings remain.
        assert_eq!(reference.get(b"user:alex"), None);
        assert_eq!(reference.get(b"user:alice"), None);
        assert_eq!(reference.get(b"user:bob"), None);
        assert_eq!(reference.get(b"sys:log"), Some(b"3".to_vec()));
        assert_eq!(reference.get(b"zzz"), Some(b"5".to_vec()));
    }
}

// ─── K2: tree-fs native op roundtrip proof ───────────────────────────────────
// Proves the four `/dir`+`/info` verifiers end-to-end on MRT: each change runs
// through the real verifier (`dispatch_extract_and_validate`) over a
// `TraceRecorder`, the emitted writes are applied + traced, and the witness is
// re-verified against the start DC and replayed by a `TraceReplayer` to recompute
// the post-op DC — matched against a reference tree that applied the same writes
// directly. This is the same record→verify-witness→replay seam the K0 spike used,
// now driven by the verifiers (incl. the move `MovePrefix` / delete `DeletePrefix`
// lowering). MRT-only — the prefix ops are an MRT capability.
#[cfg(all(test, feature = "mrt"))]
mod tree_fs_native_roundtrip_tests {
    use super::*;
    use crate::changelog::{HandleReader, KvData, LogMessage};
    use crate::ops::dispatch_extract_and_validate;
    use ffproof_tracer_shared::{TraceInterface, TraceRecorder, TraceReplayer, Tree};

    fn native_entry(
        uid: u32,
        parent_clc: [u8; 32],
        kind: u16,
        version: u16,
        payload: Vec<u8>,
    ) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Native,
                tree_path: ROOT_TREE_PATH.to_vec(),
                entries: vec![
                    KvData {
                        key: native_marker_key(),
                        value: encode_native_header(kind, version),
                    },
                    KvData {
                        key: native_payload_key(),
                        value: payload,
                    },
                ],
            },
            sig_ref: 0,
            parent_clc,
            signature: vec![],
        }
    }

    fn dir(name: &[u8]) -> tree_fs::Inode {
        tree_fs::Inode {
            version: tree_fs::INODE_VERSION,
            flags: tree_fs::NodeKind::Directory.flags(),
            author_uid: 7,
            size: 0,
            ctime: 100,
            mtime: 100,
            content_hash: [0u8; tree_fs::CONTENT_HASH_LEN],
            name: name.to_vec(),
        }
    }

    fn file(name: &[u8]) -> tree_fs::Inode {
        tree_fs::Inode {
            version: tree_fs::INODE_VERSION,
            flags: tree_fs::NodeKind::File.flags(),
            author_uid: 7,
            size: 10,
            ctime: 100,
            mtime: 100,
            content_hash: [7u8; tree_fs::CONTENT_HASH_LEN],
            name: name.to_vec(),
        }
    }

    /// Prove one change against `tree`: verify it over a recorder, apply + trace
    /// the writes, re-verify the witness against the start DC, replay it, and
    /// assert the proven post-op DC equals the directly-advanced reference tree's
    /// DC. Advances `tree` by the emitted writes and returns them.
    fn prove_change(tree: &Tree, change: &ChangelogEntry, change_id: usize) -> Vec<WriteOp> {
        let snapshot = tree.checkpoint();
        let start_dc = snapshot.root_hash();

        // Prove side: the verifier reads through a recorder over the snapshot.
        let mut recorder = TraceRecorder::new(&snapshot);
        let writes = {
            let mut reader = HandleReader(&mut recorder);
            let ctx = OpContext::for_change_id(change_id);
            dispatch_extract_and_validate(change, &mut reader, &ctx)
                .expect("op verifies on the prove side")
                .write_steps
        };
        recorder.apply(&writes).expect("recorder applies writes");
        let trace = recorder.finalize_trace().expect("finalize trace witness");

        // Verify side: authenticate the witness against the start DC, replay the
        // writes, and recompute the post-op DC.
        let mut replayer =
            TraceReplayer::new_verified(&trace, start_dc).expect("trace witness verifies");
        replayer.apply(&writes).expect("replayer applies writes");
        let proven_dc = replayer
            .root_hash()
            .expect("replayer recomputes the post-op DC");

        // Advance the reference tree and assert the proven DC matches.
        tree.apply_write_ops(&writes).expect("tree applies writes");
        assert_eq!(
            proven_dc,
            tree.root_hash(),
            "proven post-op DC must equal the reference tree DC"
        );
        writes
    }

    #[test]
    fn tree_fs_native_roundtrip() {
        let uid = 7;
        let tree = Tree::new();

        // Seed an active (non-provisional) user so the ACL check passes; the
        // status read is proven from each change's witness like any other read.
        tree.put(
            column_key("_users", uid as i64, "status"),
            encrypted_spaces_storage_encoding::stored_value::value_to_bytes(&serde_json::json!(1))
                .unwrap(),
        )
        .expect("seed user status");

        // Distinct parent CLCs → distinct CLC-derived ids.
        let pc_a = [0xA1u8; 32];
        let pc_b = [0xB2u8; 32];
        let pc_c = [0xC3u8; 32];
        let id_a = tree_fs::derive_inode_id(pc_a);
        let id_b = tree_fs::derive_inode_id(pc_b);
        let id_c = tree_fs::derive_inode_id(pc_c);
        let rkey = |path: &[tree_fs::InodeId]| tree_fs::encode_record_key(path).unwrap();

        // create dir A and dir B under root; create file C under A.
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_a,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[], &dir(b"A")).unwrap(),
            ),
            1,
        );
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_b,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[], &dir(b"B")).unwrap(),
            ),
            2,
        );
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_c,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[id_a], &file(b"C.txt")).unwrap(),
            ),
            3,
        );
        assert!(tree.get(&rkey(&[id_a])).is_some());
        assert!(tree.get(&rkey(&[id_b])).is_some());
        assert!(tree.get(&rkey(&[id_a, id_c])).is_some());

        // rename A.
        prove_change(
            &tree,
            &native_entry(
                uid,
                [0u8; 32],
                TREE_FS_RENAME_KIND,
                TREE_FS_RENAME_VERSION,
                encode_tree_fs_inode_rename_payload(&[id_a], b"A2", 500).unwrap(),
            ),
            4,
        );
        let renamed = tree_fs::Inode::decode(&tree.get(&rkey(&[id_a])).unwrap()).unwrap();
        assert_eq!(renamed.name, b"A2");
        assert_eq!(renamed.mtime, 500);

        // move A (a directory holding child C) under B — one MovePrefix relocates
        // the whole subtree (C), plus the record Delete+Put.
        prove_change(
            &tree,
            &native_entry(
                uid,
                [0u8; 32],
                TREE_FS_MOVE_KIND,
                TREE_FS_MOVE_VERSION,
                encode_tree_fs_inode_move_payload(&[id_a], &[id_b], 600).unwrap(),
            ),
            5,
        );
        assert!(
            tree.get(&rkey(&[id_a])).is_none(),
            "A's old record relocated"
        );
        assert!(
            tree.get(&rkey(&[id_a, id_c])).is_none(),
            "C relocated with A"
        );
        assert!(tree.get(&rkey(&[id_b, id_a])).is_some(), "A now under B");
        assert!(
            tree.get(&rkey(&[id_b, id_a, id_c])).is_some(),
            "C now under A under B"
        );

        // delete A (now at [B, A]) — one DeletePrefix removes C, plus the record Delete.
        prove_change(
            &tree,
            &native_entry(
                uid,
                [0u8; 32],
                TREE_FS_DELETE_KIND,
                TREE_FS_DELETE_VERSION,
                encode_tree_fs_inode_delete_payload(&[id_b, id_a]).unwrap(),
            ),
            6,
        );

        // Final model: only B remains under root; A and C are gone.
        assert!(tree.get(&rkey(&[id_b])).is_some(), "B remains");
        assert!(tree.get(&rkey(&[id_b, id_a])).is_none(), "A deleted");
        assert!(
            tree.get(&rkey(&[id_b, id_a, id_c])).is_none(),
            "C deleted with A"
        );
    }

    #[test]
    fn tree_fs_native_delete_empty_dir() {
        // Deleting a childless directory: its container holds only the create-time
        // sentinel (`tree_fs_dir_sentinel_key`), and the delete (DeletePrefix
        // container + Delete record) removes both. `DeletePrefix` is also tolerant
        // of an absent prefix, so this would succeed even without the sentinel.
        let uid = 7;
        let tree = Tree::new();
        tree.put(
            column_key("_users", uid as i64, "status"),
            encrypted_spaces_storage_encoding::stored_value::value_to_bytes(&serde_json::json!(1))
                .unwrap(),
        )
        .unwrap();
        let pc_a = [0xA1u8; 32];
        let id_a = tree_fs::derive_inode_id(pc_a);
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_a,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[], &dir(b"empty")).unwrap(),
            ),
            1,
        );
        assert!(tree
            .get(&tree_fs::encode_record_key(&[id_a]).unwrap())
            .is_some());
        prove_change(
            &tree,
            &native_entry(
                uid,
                [0u8; 32],
                TREE_FS_DELETE_KIND,
                TREE_FS_DELETE_VERSION,
                encode_tree_fs_inode_delete_payload(&[id_a]).unwrap(),
            ),
            2,
        );
        assert!(tree
            .get(&tree_fs::encode_record_key(&[id_a]).unwrap())
            .is_none());
    }

    #[test]
    fn tree_fs_native_move_empty_dir() {
        // Moving a *childless* directory proves end-to-end: its `/dir` container
        // holds only the create-time sentinel, so the move's `MovePrefix` has a
        // present source prefix and relocates the (sentinel-only) container plus
        // the record. Without the sentinel, merk's `MovePrefix` would error on the
        // absent source prefix — the gap this fixes.
        let uid = 7;
        let tree = Tree::new();
        tree.put(
            column_key("_users", uid as i64, "status"),
            encrypted_spaces_storage_encoding::stored_value::value_to_bytes(&serde_json::json!(1))
                .unwrap(),
        )
        .unwrap();
        let pc_src = [0xA1u8; 32];
        let pc_dst = [0xB2u8; 32];
        let id_src = tree_fs::derive_inode_id(pc_src);
        let id_dst = tree_fs::derive_inode_id(pc_dst);
        let rkey = |path: &[tree_fs::InodeId]| tree_fs::encode_record_key(path).unwrap();

        // Create the empty source dir and a destination dir, both under root.
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_src,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[], &dir(b"empty")).unwrap(),
            ),
            1,
        );
        prove_change(
            &tree,
            &native_entry(
                uid,
                pc_dst,
                TREE_FS_CREATE_KIND,
                TREE_FS_CREATE_VERSION,
                encode_tree_fs_inode_create_payload(&[], &dir(b"dest")).unwrap(),
            ),
            2,
        );

        // Move the empty source dir under the destination dir.
        prove_change(
            &tree,
            &native_entry(
                uid,
                [0u8; 32],
                TREE_FS_MOVE_KIND,
                TREE_FS_MOVE_VERSION,
                encode_tree_fs_inode_move_payload(&[id_src], &[id_dst], 600).unwrap(),
            ),
            3,
        );

        assert!(tree.get(&rkey(&[id_src])).is_none(), "source record moved");
        assert!(
            tree.get(&rkey(&[id_dst, id_src])).is_some(),
            "source now under destination"
        );
    }
}
