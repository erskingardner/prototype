//! Client-side native-op invocation (filesystem-scoped).
//!
//! A *native* op encodes a mutation as a fixed wire shape — a 4-byte marker
//! header plus a per-kind payload — dispatched to the hardcoded `NativeOp`
//! verifier, instead of routing column writes through the generic
//! [`ChangeBuilder`](crate::changelog::ChangeBuilder) and a stored KDL action.
//!
//! Each `submit_*_native` builds that two-kv `OpType::Native` entry by hand
//! (the generic builder only emits column kvs) while reusing the data-driven
//! path's content handling: hash-backed columns are encrypted via the same
//! [`encrypt_query_fields`](crate::crypto) call and hash-backed exactly as
//! `apply_hash_backed_storage` would, so their bytes ride in
//! `change.hashed_values` and the payload carries only their digest; encrypted
//! (but not hash-backed) columns ride in the payload verbatim. The
//! submit→apply→cache tail mirrors the data-driven mutators.

use crate::file::File;
use crate::Space;
use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::merk_storage::get_row_data_from_query;
use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
use encrypted_spaces_backend::sign_change::sign_change;
use encrypted_spaces_changelog_core::changelog::{Change, OpType, ROOT_TREE_PATH};
use encrypted_spaces_changelog_core::{
    encode_add_inode_payload, encode_delete_inode_recursive_payload, encode_move_inode_payload,
    encode_native_header, encode_rename_inode_payload, encode_tree_fs_inode_create_payload,
    encode_tree_fs_inode_delete_payload, encode_tree_fs_inode_move_payload,
    encode_tree_fs_inode_rename_payload, encode_update_message_payload, tree_fs, WriteOp,
    ADD_INODE_KIND, ADD_INODE_VERSION, DELETE_INODE_RECURSIVE_KIND, DELETE_INODE_RECURSIVE_VERSION,
    MOVE_INODE_KIND, MOVE_INODE_VERSION, RENAME_INODE_KIND, RENAME_INODE_VERSION,
    TREE_FS_CREATE_KIND, TREE_FS_CREATE_VERSION, TREE_FS_DELETE_KIND, TREE_FS_DELETE_VERSION,
    TREE_FS_MOVE_KIND, TREE_FS_MOVE_VERSION, TREE_FS_RENAME_KIND, TREE_FS_RENAME_VERSION,
    UPDATE_MESSAGE_KIND, UPDATE_MESSAGE_VERSION,
};
use encrypted_spaces_storage_encoding::hashstore_hash;
use encrypted_spaces_storage_encoding::keys::{native_marker_key, native_payload_key};

/// The app table the native `update_message` op edits.
const MESSAGES_TABLE: &str = "messages";
const INODES_TABLE: &str = "inodes";

/// Tree-filesystem handle: root-to-node inode ids. The root handle is `vec![]`.
pub type FsHandle = tree_fs::InodePath;

/// Wire representation for [`FsHandle`]: each inode id as a 64-character hex string.
pub type FsHandleWire = Vec<String>;

/// Wire conversion helpers for the inode-id tree filesystem handle.
pub trait FsHandleWireCodec: Sized {
    fn into_wire(self) -> FsHandleWire;
    fn from_wire(wire: FsHandleWire) -> Result<Self>;
}

impl FsHandleWireCodec for FsHandle {
    fn into_wire(self) -> FsHandleWire {
        self.into_iter().map(hex::encode).collect()
    }

    fn from_wire(wire: FsHandleWire) -> Result<Self> {
        wire.into_iter()
            .map(|component| decode_fs_handle_component(&component))
            .collect()
    }
}

/// Convert a tree-fs file content hash from the app-facing hex form to the raw
/// 32-byte codec value.
pub fn tree_fs_content_hash_from_hex(hex_hash: &str) -> Result<[u8; tree_fs::CONTENT_HASH_LEN]> {
    decode_fixed_hex_32(hex_hash, "tree_fs content_hash")
}

/// Convert a raw tree-fs content hash back to the app-facing hex form.
pub fn tree_fs_content_hash_to_hex(hash: &[u8; tree_fs::CONTENT_HASH_LEN]) -> String {
    hex::encode(hash)
}

/// Build the raw record key for a tree-fs inode handle.
pub fn tree_fs_record_key(handle: &[tree_fs::InodeId]) -> Result<Vec<u8>> {
    tree_fs::encode_record_key(handle)
        .map_err(|e| SdkError::ValidationError(format!("tree_fs record key: {e}")))
}

/// Build the raw directory container prefix for a tree-fs inode handle.
pub fn tree_fs_container_prefix(handle: &[tree_fs::InodeId]) -> Result<Vec<u8>> {
    tree_fs::encode_container_prefix(handle)
        .map_err(|e| SdkError::ValidationError(format!("tree_fs container prefix: {e}")))
}

impl Space {
    /// Edit `messages.content` for `message_id` via the native `update_message`
    /// op (rather than the data-driven action).
    ///
    /// `content` is encrypted with the current key (same path as the
    /// data-driven builder) and hash-backed: the encrypted bytes go into
    /// `change.hashed_values` and the 40-byte payload carries only their
    /// digest. The signed `Native` entry is submitted, then — on acceptance —
    /// validated, applied, and folded into the local cache, advancing the
    /// submitter's DC / CLC / sigref state just like the data-driven mutators.
    ///
    /// Returns the server's `rows_affected`. Ownership is enforced server-side
    /// by `NativeOp::extract_and_validate`; a non-owner edit is rejected there.
    pub async fn submit_update_message_native(
        &self,
        message_id: i64,
        content: &str,
    ) -> Result<usize> {
        let change = self
            .build_update_message_native_change(message_id, content)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    /// Atomically rename `inodes.<inode_id>` (its `name` and `mtime`) via the
    /// native `rename_inode` op (rather than the data-driven action).
    ///
    /// `name` (hash-backed Text) and `mtime` (encrypted Integer) are encrypted
    /// client-side through the same [`encrypt_query_fields`](crate::crypto)
    /// pipeline the data-driven path uses, so the stored bytes are
    /// byte-identical: the `name` ciphertext is hash-backed (bytes in
    /// `change.hashed_values`, 32-byte digest in the payload) while the `mtime`
    /// ciphertext rides in the payload verbatim. A missing inode is a graceful
    /// no-op (server-side existence probe), returning `0` rows.
    ///
    /// Returns the server's `rows_affected` (`1` on a present inode, `0` when it
    /// does not exist).
    pub async fn submit_rename_inode_native(
        &self,
        inode_id: i64,
        name: &str,
        mtime: i64,
    ) -> Result<usize> {
        let change = self
            .build_rename_inode_native_change(inode_id, name, mtime)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    /// Move `inodes.<inode_id>` to `new_parent_id` via the native `move_inode`
    /// op (rather than the data-driven action).
    ///
    /// `parent_id` is plaintext and indexed, so it rides in the payload as an
    /// `i64`; `mtime` is encrypted client-side through the same
    /// [`encrypt_query_fields`](crate::crypto) pipeline the data-driven action
    /// uses and its stored ciphertext bytes ride in the payload verbatim. The
    /// move carries no hash-backed columns, so the request sidecar is empty.
    pub async fn submit_move_inode_native(
        &self,
        inode_id: i64,
        new_parent_id: i64,
        mtime: i64,
    ) -> Result<usize> {
        let change = self
            .build_move_inode_native_change(inode_id, new_parent_id, mtime)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    /// Insert one `inodes` row via the native `add_inode` op (rather than the
    /// data-driven action) — both a *file* and a *folder* go through this one
    /// verb, one wire format.
    ///
    /// `name` and `mime_type` are hash-backed Text columns and `size`/`ctime`/
    /// `mtime` are encrypted Integers; all five are encrypted client-side
    /// through the same [`encrypt_query_fields`](crate::crypto) pipeline the
    /// data-driven insert uses, so the stored bytes are byte-identical. Two
    /// content digests (`name`, `mime_type`) ride in `change.hashed_values`,
    /// while the three encrypted-Integer ciphertexts ride in the payload
    /// verbatim. `file_hash` is the pre-uploaded blob fileref: a `File::Data` is
    /// uploaded first (yielding its hash), a `File::Hash` (e.g. a folder's
    /// all-zero hash) passes through unchanged — the hex string rides in the
    /// payload as a plaintext column. `size` is passed explicitly (the byte
    /// length for a file, `0` for a folder).
    ///
    /// The row id is server-assigned from the `inodes` `next_id` counter and
    /// recovered from the proven writes. Type/parent-folder/self-parent
    /// invariants are enforced server-side by `NativeOp::extract_and_validate`.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_add_inode_native(
        &self,
        parent_id: i64,
        author_id: i64,
        name: &str,
        inode_type: i64,
        size: i64,
        ctime: i64,
        mtime: i64,
        mime_type: &str,
        file_hash: File,
    ) -> Result<i64> {
        let change = self
            .build_add_inode_native_change(
                parent_id, author_id, name, inode_type, size, ctime, mtime, mime_type, file_hash,
            )
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        crate::cache::new_row_id_for_table(self, &writes, INODES_TABLE).ok_or_else(|| {
            SdkError::InsertError(
                "add_inode: native insert produced no new inodes row id".to_string(),
            )
        })
    }

    /// Delete an `inodes` row and its full descendant subtree via the native
    /// `delete_inode_recursive` op.
    ///
    /// The payload carries only the target inode id. The verifier derives the
    /// subtree server-side from the `parent_id` index and emits only Deletes, so
    /// the request sidecar is empty. A missing target is a graceful no-op
    /// (`rows_affected == 0`), matching the raw recursive delete path.
    pub async fn submit_delete_inode_recursive_native(&self, inode_id: i64) -> Result<usize> {
        let change = self
            .build_delete_inode_recursive_native_change(inode_id)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    async fn build_update_message_native_change(
        &self,
        message_id: i64,
        content: &str,
    ) -> Result<Change> {
        // Encrypt the content through the same query path the data-driven
        // builder uses, then serialize it to the stored column bytes.
        let mut query = Query::new(
            MESSAGES_TABLE.to_string(),
            QueryOperation::Update(vec![(
                "content".to_string(),
                QueryParam::Text(content.to_string()),
            )]),
        );
        crate::crypto::encrypt_query_fields(&mut query, self).await?;
        let (_, column_data) = get_row_data_from_query(&query)?;
        let content_bytes = column_data
            .into_iter()
            .find(|(col, _)| col == "content")
            .map(|(_, bytes)| bytes)
            .ok_or_else(|| {
                SdkError::ValidationError(
                    "update_message: content column missing after encryption".to_string(),
                )
            })?;

        // Hash-back the content exactly as `apply_hash_backed_storage` does:
        // the digest rides in the payload, the bytes in the sidecar.
        let content_digest = hashstore_hash(&content_bytes);

        let marker_value = encode_native_header(UPDATE_MESSAGE_KIND, UPDATE_MESSAGE_VERSION);
        let payload_value = encode_update_message_payload(message_id, &content_digest);
        let mut change = self.new_native_change(&marker_value, &payload_value, "update_message")?;
        change.hashed_values.insert(content_digest, content_bytes);
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    async fn build_rename_inode_native_change(
        &self,
        inode_id: i64,
        name: &str,
        mtime: i64,
    ) -> Result<Change> {
        // Encrypt both updated columns (`name` Text + `mtime` Integer) through
        // the same query path the data-driven `rename_inode` action uses, so the
        // stored bytes are byte-identical. `name` is hash-backed; `mtime` is not.
        let mut query = Query::new(
            INODES_TABLE.to_string(),
            QueryOperation::Update(vec![
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("mtime".to_string(), QueryParam::Integer(mtime)),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut query, self).await?;
        let (_, column_data) = get_row_data_from_query(&query)?;
        let column_bytes = |col: &str| -> Result<Vec<u8>> {
            column_data
                .iter()
                .find(|(c, _)| c == col)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "rename_inode: {col} column missing after encryption"
                    ))
                })
        };
        // `name` (Text, hash-backed): the encrypted bytes ride in the sidecar,
        // the 32-byte digest in the payload — same pipeline as `update_message`.
        let name_bytes = column_bytes("name")?;
        let name_digest = hashstore_hash(&name_bytes);
        // `mtime` (encrypted Integer, NOT hash-backed): the ciphertext bytes ride
        // in the payload verbatim — never re-encrypted or rebuilt from the `i64`.
        let mtime_ciphertext = column_bytes("mtime")?;

        let marker_value = encode_native_header(RENAME_INODE_KIND, RENAME_INODE_VERSION);
        let payload_value = encode_rename_inode_payload(inode_id, &name_digest, &mtime_ciphertext);
        let mut change = self.new_native_change(&marker_value, &payload_value, "rename_inode")?;
        change.hashed_values.insert(name_digest, name_bytes);
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    async fn build_move_inode_native_change(
        &self,
        inode_id: i64,
        new_parent_id: i64,
        mtime: i64,
    ) -> Result<Change> {
        // Encrypt only `mtime` through the same query path the data-driven
        // `move_inode` action uses. `parent_id` is plaintext and is encoded as
        // the payload's raw scalar instead of being routed through this query.
        let mut query = Query::new(
            INODES_TABLE.to_string(),
            QueryOperation::Update(vec![("mtime".to_string(), QueryParam::Integer(mtime))]),
        );
        crate::crypto::encrypt_query_fields(&mut query, self).await?;
        let (_, column_data) = get_row_data_from_query(&query)?;
        let mtime_ciphertext = column_data
            .iter()
            .find(|(c, _)| c == "mtime")
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| {
                SdkError::ValidationError(
                    "move_inode: mtime column missing after encryption".to_string(),
                )
            })?;

        let marker_value = encode_native_header(MOVE_INODE_KIND, MOVE_INODE_VERSION);
        let payload_value = encode_move_inode_payload(inode_id, new_parent_id, &mtime_ciphertext);
        let mut change = self.new_native_change(&marker_value, &payload_value, "move_inode")?;
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_add_inode_native_change(
        &self,
        parent_id: i64,
        author_id: i64,
        name: &str,
        inode_type: i64,
        size: i64,
        ctime: i64,
        mtime: i64,
        mime_type: &str,
        file_hash: File,
    ) -> Result<Change> {
        // Resolve the `file_hash` fileref: a `File::Data` is uploaded (encrypted
        // to the file store, yielding its hex hash); a `File::Hash` (a folder's
        // all-zero hash, or an already-uploaded file) passes through unchanged.
        // The hex string rides in the payload as a plaintext column.
        let uploaded = self.file().upload(file_hash).await?;
        let file_hash = uploaded.hash()?.to_string();

        // Encrypt the two hash-backed Text columns (`name`, `mime_type`) and the
        // three encrypted Integers (`size`, `ctime`, `mtime`) through the same
        // query path the data-driven insert uses, so the stored bytes are
        // byte-identical. Folder mode's empty `mime_type` and `size`/`ctime`/
        // `mtime` of `0` are ordinary values that encrypt + round-trip the same
        // way.
        let mut query = Query::new(
            INODES_TABLE.to_string(),
            QueryOperation::Insert(vec![
                ("name".to_string(), QueryParam::Text(name.to_string())),
                (
                    "mime_type".to_string(),
                    QueryParam::Text(mime_type.to_string()),
                ),
                ("size".to_string(), QueryParam::Integer(size)),
                ("ctime".to_string(), QueryParam::Integer(ctime)),
                ("mtime".to_string(), QueryParam::Integer(mtime)),
            ]),
        );
        crate::crypto::encrypt_query_fields(&mut query, self).await?;
        let (_, column_data) = get_row_data_from_query(&query)?;
        let column_bytes = |col: &str| -> Result<Vec<u8>> {
            column_data
                .iter()
                .find(|(c, _)| c == col)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "add_inode: {col} column missing after encryption"
                    ))
                })
        };
        // `name` / `mime_type` (Text, hash-backed): the encrypted bytes ride in
        // the sidecar, the 32-byte digests in the payload — the two-digest insert.
        let name_bytes = column_bytes("name")?;
        let mime_type_bytes = column_bytes("mime_type")?;
        let name_digest = hashstore_hash(&name_bytes);
        let mime_type_digest = hashstore_hash(&mime_type_bytes);
        // `size` / `ctime` / `mtime` (encrypted Integers, NOT hash-backed): the
        // ciphertext bytes ride in the payload verbatim.
        let size_ciphertext = column_bytes("size")?;
        let ctime_ciphertext = column_bytes("ctime")?;
        let mtime_ciphertext = column_bytes("mtime")?;

        let marker_value = encode_native_header(ADD_INODE_KIND, ADD_INODE_VERSION);
        let payload_value = encode_add_inode_payload(
            parent_id,
            author_id,
            inode_type,
            &size_ciphertext,
            &ctime_ciphertext,
            &mtime_ciphertext,
            &name_digest,
            &mime_type_digest,
            &file_hash,
        );
        let mut change = self.new_native_change(&marker_value, &payload_value, "add_inode")?;
        // Both hash-backed columns ride in the request sidecar.
        change.hashed_values.insert(name_digest, name_bytes);
        change
            .hashed_values
            .insert(mime_type_digest, mime_type_bytes);
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    async fn build_delete_inode_recursive_native_change(&self, inode_id: i64) -> Result<Change> {
        let marker_value =
            encode_native_header(DELETE_INODE_RECURSIVE_KIND, DELETE_INODE_RECURSIVE_VERSION);
        let payload_value = encode_delete_inode_recursive_payload(inode_id);
        let mut change =
            self.new_native_change(&marker_value, &payload_value, "delete_inode_recursive")?;
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    // ─── Tree-fs native ops (Phase B) ───────────────────────────────────────
    // A separate filesystem surface from the `inodes` table: hierarchical
    // records under the raw `/_fs` namespace, addressed by a root-to-node
    // inode-id path handle rather than a table row id.

    /// Create one tree-filesystem node under `parent` via the native tree-FS
    /// create op. The returned handle is the newly allocated hierarchical path.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_tree_fs_create_native(
        &self,
        parent: FsHandle,
        author_uid: u32,
        kind: tree_fs::NodeKind,
        name: Vec<u8>,
        size: u64,
        ctime: i64,
        mtime: i64,
        content_hash: [u8; tree_fs::CONTENT_HASH_LEN],
    ) -> Result<FsHandle> {
        let change = self
            .build_tree_fs_create_native_change(
                parent.clone(),
                author_uid,
                kind,
                name,
                size,
                ctime,
                mtime,
                content_hash,
            )
            .await?;
        let accepted_child_id = tree_fs::derive_inode_id(change.entry.parent_clc);

        let response = self.transport.submit_change(&change, vec![]).await?;
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        let handle = tree_fs_created_handle_from_writes(&parent, &writes).ok_or_else(|| {
            SdkError::InsertError(
                "tree_fs_create: native create produced no child record".to_string(),
            )
        })?;
        if handle.last() != Some(&accepted_child_id) {
            return Err(SdkError::InsertError(
                "tree_fs_create: native create returned an unexpected child id".to_string(),
            ));
        }
        Ok(handle)
    }

    /// Rename a tree-filesystem node via its hierarchical handle.
    pub async fn submit_tree_fs_rename_native(
        &self,
        id: FsHandle,
        name: Vec<u8>,
        mtime: i64,
    ) -> Result<usize> {
        let change = self
            .build_tree_fs_rename_native_change(id, name, mtime)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        if response.rows_affected == 0 {
            return Ok(0);
        }
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    /// Move a tree-filesystem subtree and return the moved root's new handle.
    pub async fn submit_tree_fs_move_native(
        &self,
        id: FsHandle,
        new_parent: FsHandle,
        mtime: i64,
    ) -> Result<Option<FsHandle>> {
        let change = self
            .build_tree_fs_move_native_change(id, new_parent.clone(), mtime)
            .await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        if response.rows_affected == 0 {
            return Ok(None);
        }
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(tree_fs_created_handle_from_writes(&new_parent, &writes))
    }

    /// Recursively delete a tree-filesystem subtree via native tree-FS delete.
    pub async fn submit_tree_fs_delete_native(&self, id: FsHandle) -> Result<usize> {
        let change = self.build_tree_fs_delete_native_change(id).await?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        if response.rows_affected == 0 {
            return Ok(0);
        }
        let writes = self.validate_and_apply_change(&change.entry, &response)?;
        crate::cache::update_cache_from_proven_writes(self, &change, &writes).await;
        Ok(response.rows_affected as usize)
    }

    /// Raw-read and decode one tree-fs inode record at this client's current
    /// data commitment.
    pub async fn read_tree_fs_inode_native(
        &self,
        id: &[tree_fs::InodeId],
    ) -> Result<Option<tree_fs::Inode>> {
        let key = tree_fs_record_key(id)?;
        self.raw_read_key(key)
            .await?
            .map(|bytes| {
                tree_fs::Inode::decode(&bytes)
                    .map_err(|e| SdkError::ValidationError(format!("tree_fs inode decode: {e}")))
            })
            .transpose()
    }

    /// Raw prefix-scan a tree-fs directory container at this client's current
    /// data commitment.
    pub async fn raw_read_tree_fs_container_native(
        &self,
        id: &[tree_fs::InodeId],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.raw_read_prefix(tree_fs_container_prefix(id)?).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_tree_fs_create_native_change(
        &self,
        parent: FsHandle,
        author_uid: u32,
        kind: tree_fs::NodeKind,
        name: Vec<u8>,
        size: u64,
        ctime: i64,
        mtime: i64,
        content_hash: [u8; tree_fs::CONTENT_HASH_LEN],
    ) -> Result<Change> {
        let inode = tree_fs::Inode {
            version: tree_fs::INODE_VERSION,
            flags: kind.flags(),
            author_uid,
            size,
            ctime,
            mtime,
            content_hash,
            name,
        };
        let payload_value = encode_tree_fs_inode_create_payload(&parent, &inode)
            .map_err(|e| SdkError::ValidationError(format!("tree_fs_create: {e}")))?;
        self.build_tree_fs_native_change(
            "tree_fs_create",
            TREE_FS_CREATE_KIND,
            TREE_FS_CREATE_VERSION,
            payload_value,
        )
        .await
    }

    async fn build_tree_fs_rename_native_change(
        &self,
        id: FsHandle,
        name: Vec<u8>,
        mtime: i64,
    ) -> Result<Change> {
        let payload_value = encode_tree_fs_inode_rename_payload(&id, &name, mtime)
            .map_err(|e| SdkError::ValidationError(format!("tree_fs_rename: {e}")))?;
        self.build_tree_fs_native_change(
            "tree_fs_rename",
            TREE_FS_RENAME_KIND,
            TREE_FS_RENAME_VERSION,
            payload_value,
        )
        .await
    }

    async fn build_tree_fs_move_native_change(
        &self,
        id: FsHandle,
        new_parent: FsHandle,
        mtime: i64,
    ) -> Result<Change> {
        let payload_value = encode_tree_fs_inode_move_payload(&id, &new_parent, mtime)
            .map_err(|e| SdkError::ValidationError(format!("tree_fs_move: {e}")))?;
        self.build_tree_fs_native_change(
            "tree_fs_move",
            TREE_FS_MOVE_KIND,
            TREE_FS_MOVE_VERSION,
            payload_value,
        )
        .await
    }

    async fn build_tree_fs_delete_native_change(&self, id: FsHandle) -> Result<Change> {
        let payload_value = encode_tree_fs_inode_delete_payload(&id)
            .map_err(|e| SdkError::ValidationError(format!("tree_fs_delete: {e}")))?;
        self.build_tree_fs_native_change(
            "tree_fs_delete",
            TREE_FS_DELETE_KIND,
            TREE_FS_DELETE_VERSION,
            payload_value,
        )
        .await
    }

    /// Tree-fs envelopes carry no hash-backed sidecar, so this is just the
    /// shared envelope build + sign over a tree-fs payload.
    async fn build_tree_fs_native_change(
        &self,
        op_name: &str,
        kind: u16,
        version: u16,
        payload_value: Vec<u8>,
    ) -> Result<Change> {
        let marker_value = encode_native_header(kind, version);
        let mut change = self.new_native_change(&marker_value, &payload_value, op_name)?;
        self.sign_native_change(&mut change).await;
        Ok(change)
    }

    /// Assemble the two-kv `OpType::Native` envelope from a marker header and a
    /// per-kind payload, stamping the signer uid and the client's head so the
    /// server's strict-freshness guard accepts a change built at head. The
    /// caller adds any hash-backed sidecar bytes and signs.
    fn new_native_change(
        &self,
        marker_value: &[u8],
        payload_value: &[u8],
        op_label: &str,
    ) -> Result<Change> {
        let marker_key = native_marker_key();
        let payload_key = native_payload_key();

        let (uid, current_change_id, my_last_change_id, current_clc) =
            self.with_state(|state| {
                let uid = state.auth_context.uid.ok_or_else(|| {
                    SdkError::DatabaseError("User is not authenticated".to_string())
                })?;
                let clc_root: [u8; 32] = state.current_clc_state.root.into();
                Ok::<_, SdkError>((
                    uid as u32,
                    state.current_change_id,
                    state.my_last_change_id,
                    clc_root,
                ))
            })?;

        let keys: [&[u8]; 2] = [marker_key.as_slice(), payload_key.as_slice()];
        let values: [&[u8]; 2] = [marker_value, payload_value];
        Change::new(
            OpType::Native,
            uid,
            ROOT_TREE_PATH,
            &keys,
            &values,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| {
            SdkError::DatabaseError(format!("{op_label}: failed to build native change: {e}"))
        })
    }

    /// Sign the native entry in place with the caller's auth key pair.
    async fn sign_native_change(&self, change: &mut Change) {
        let km = self.key_manager.lock().await;
        sign_change(&mut change.entry, km.auth_key_pair());
    }
}

/// Recover a freshly created tree-fs child's handle from the proven writes:
/// the one `Put` whose decoded path is a direct child of `parent`. Used by
/// create (and by move, to report the moved subtree's new root handle).
fn tree_fs_created_handle_from_writes(
    parent: &[tree_fs::InodeId],
    writes: &[WriteOp],
) -> Option<FsHandle> {
    writes.iter().find_map(|op| {
        let WriteOp::Put { key, .. } = op else {
            return None;
        };
        let path = tree_fs::decode_record_key::<tree_fs::InodePath>(key).ok()?;
        if path.len() == parent.len() + 1 && &path[..parent.len()] == parent {
            Some(path)
        } else {
            None
        }
    })
}

fn decode_fs_handle_component(component: &str) -> Result<tree_fs::InodeId> {
    debug_assert_eq!(tree_fs::CONTENT_HASH_LEN, tree_fs::INODE_ID_LEN);
    let id = decode_fixed_hex_32(component, "tree_fs handle component")?;
    tree_fs::validate_inode_id(&id)
        .map_err(|e| SdkError::ValidationError(format!("tree_fs handle component: {e}")))?;
    Ok(id)
}

fn decode_fixed_hex_32(
    hex_value: &str,
    field_name: &str,
) -> Result<[u8; tree_fs::CONTENT_HASH_LEN]> {
    let bytes = hex::decode(hex_value)
        .map_err(|e| SdkError::ValidationError(format!("{field_name}: invalid hex: {e}")))?;
    if bytes.len() != tree_fs::CONTENT_HASH_LEN {
        return Err(SdkError::ValidationError(format!(
            "{field_name}: expected {} bytes, got {}",
            tree_fs::CONTENT_HASH_LEN,
            bytes.len()
        )));
    }
    let mut out = [0u8; tree_fs::CONTENT_HASH_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "local-transport"))]
mod tree_fs_tests {
    use super::*;
    use crate::{ApplicationSchema, LocalTransport};

    fn schema() -> ApplicationSchema {
        ApplicationSchema::for_testing(vec![], crate::testing::initial_internal_data_commitment())
    }

    async fn create_space() -> Result<Space> {
        let transport = LocalTransport::in_memory().await?;
        Space::create(transport, schema()).await
    }

    #[test]
    fn fs_handle_wire_roundtrip() -> Result<()> {
        let root: FsHandle = Vec::new();
        assert_eq!(FsHandle::from_wire(root.clone().into_wire())?, root);

        let handle: FsHandle = vec![[1u8; tree_fs::INODE_ID_LEN], [2u8; tree_fs::INODE_ID_LEN]];
        let wire = handle.clone().into_wire();
        assert_eq!(wire[0], "01".repeat(tree_fs::INODE_ID_LEN));
        assert_eq!(wire[1], "02".repeat(tree_fs::INODE_ID_LEN));
        assert_eq!(FsHandle::from_wire(wire)?, handle);

        assert!(FsHandle::from_wire(vec!["f".to_string()]).is_err());
        assert!(FsHandle::from_wire(vec!["00".to_string()]).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn submit_tree_fs_create_returns_accepted_id() -> Result<()> {
        let space = create_space().await?;
        let parent_clc = space.current_clc();
        let expected_id = tree_fs::derive_inode_id(parent_clc);

        let handle = space
            .submit_tree_fs_create_native(
                Vec::new(),
                space.uid().expect("test space has uid"),
                tree_fs::NodeKind::File,
                b"accepted.txt".to_vec(),
                12,
                100,
                100,
                [7u8; tree_fs::CONTENT_HASH_LEN],
            )
            .await?;

        assert_eq!(handle.len(), 1);
        assert_eq!(handle[0], expected_id);

        let inode = space
            .read_tree_fs_inode_native(&handle)
            .await?
            .expect("created inode is readable");
        assert_eq!(inode.name, b"accepted.txt");
        assert_eq!(inode.size, 12);
        assert_eq!(inode.content_hash, [7u8; tree_fs::CONTENT_HASH_LEN]);
        Ok(())
    }
}
