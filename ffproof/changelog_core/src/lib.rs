// Core modules (merk-only)
pub mod changelog;
pub mod mmr_tree;
mod native_ops;
pub mod ops;
pub mod time;
/// Shared wire codec for the relative-inode tree filesystem (Phase B / tree-fs):
/// record keys under the raw `/_fs` namespace + canonical `Inode` bytes.
/// One source of truth for the SDK, the in-guest verifier, and the demo helpers.
pub mod tree_fs;

// Native-op wire codec re-exported for the server (decode native payloads to find
// hash-backed digests + dispatch) and the SDK — same source of truth as the verifier.
pub use native_ops::{
    decode_add_inode_payload, decode_delete_inode_recursive_payload, decode_move_inode_payload,
    decode_native_header, decode_rename_inode_payload, decode_tree_fs_inode_create_payload,
    decode_tree_fs_inode_delete_payload, decode_tree_fs_inode_move_payload,
    decode_tree_fs_inode_rename_payload, decode_update_message_payload, encode_add_inode_payload,
    encode_delete_inode_recursive_payload, encode_move_inode_payload, encode_native_header,
    encode_rename_inode_payload, encode_tree_fs_inode_create_payload,
    encode_tree_fs_inode_delete_payload, encode_tree_fs_inode_move_payload,
    encode_tree_fs_inode_rename_payload, encode_update_message_payload, AddInodePayload,
    TreeFsInodeCreatePayload, TreeFsInodeMovePayload, TreeFsInodeRenamePayload, ADD_INODE_KIND,
    ADD_INODE_VERSION, DELETE_INODE_RECURSIVE_KIND, DELETE_INODE_RECURSIVE_VERSION,
    MOVE_INODE_KIND, MOVE_INODE_VERSION, RENAME_INODE_KIND, RENAME_INODE_VERSION,
    TREE_FS_CREATE_KIND, TREE_FS_CREATE_VERSION, TREE_FS_DELETE_KIND, TREE_FS_DELETE_VERSION,
    TREE_FS_MOVE_KIND, TREE_FS_MOVE_VERSION, TREE_FS_RENAME_KIND, TREE_FS_RENAME_VERSION,
    UPDATE_MESSAGE_KIND, UPDATE_MESSAGE_VERSION,
};

// Re-export key construction from storage-encoding
pub use encrypted_spaces_storage_encoding::encode_column_names;
pub use encrypted_spaces_storage_encoding::keys::{
    acl_only_via_actions_key, acl_rule_key, row_prefix, schema_columns_key, users_row_key,
    LISTS_TABLE, RETENTION_TABLE, USERS_TABLE,
};

// Re-export merk hash test for zkVM verification
pub use merk::zkvm_hash_tests;

pub use ffproof_tracer_shared::{prefix_successor, ProvenRead, ReadOp};
// merk's traced-handle seam types used by the verify path (`changelog`) and the
// ops' write vocabulary. `WriteOp` replaces `BatchOp` on the live op/seam path;
// `TraceReplayer` + `TraceReader`/`TraceInterface` drive verification.
pub use ffproof_tracer_shared::{TraceInterface, TraceReader, TraceReplayer, WriteOp};

/// The single `OpReader` adapter over a merk traced handle, shared by the
/// prove (`prover.rs`), verify (`changelog.rs`), and storage (`proofs.rs`) seams.
pub use changelog::HandleReader;
