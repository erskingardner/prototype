//! Test utilities for creating a mock server with ChangeLog and ChangeResponse data
//!
//! This crate provides helper functions to generate test data for changelog-related tests.
//! It requires the full backend server infrastructure to create realistic test fixtures.

use base64::Engine as _;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::merk_storage::stored_value::{bytes_to_value, value_to_bytes};
use encrypted_spaces_backend::merk_storage::{
    build_column_kv_vecs, column_key, column_key_placeholder, get_row_data_from_query, Op,
};
use encrypted_spaces_backend::query::{Query, QueryOperation, QueryParam};
use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};
use encrypted_spaces_backend::sign_change::sign_change;
use encrypted_spaces_backend::storage::Storage;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_backend_server::app_config::{BootstrapDataSource, SpaceInitConfig};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeLog, ChangeResponse, ChangelogEntry, HashedValues, LogMessage, OpType,
    ROOT_TREE_PATH,
};
use encrypted_spaces_changelog_core::piece_text::{
    BufferCoord, InsertedBufferManifest, PieceTextAddress, PieceTextEditEnvelopeV1,
    PieceTextEditItemManifest, PieceTextEditManifest, PIECE_TEXT_ENVELOPE_VERSION_V1,
};
use encrypted_spaces_changelog_core::piece_text_cleanup::{
    PieceTextCleanupBuffersEnvelopeV1, PieceTextCleanupPiecesEnvelopeV1, PieceTextCleanupRunV1,
    MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS, PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
};
use encrypted_spaces_crypto::signature::{Ed25519Signature, SignatureKeyPair};
use encrypted_spaces_storage_encoding::keys::{
    encode_list_parent, index_key, list_parent_key, piece_coords_head_key,
    piece_coords_next_list_number_key, piece_coords_parent_key, piece_coords_tail_key,
    row_id_to_bytes, PIECE_COORDS_TABLE,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Default UID used for test changes
pub const TEST_CLIENT_UID: u32 = 1;

/// Generate and store fresh test keys signing keys for each user
static TEST_AUTH_KEYS: OnceLock<Mutex<HashMap<u32, SignatureKeyPair<Ed25519Signature>>>> =
    OnceLock::new();

fn test_auth_keys() -> &'static Mutex<HashMap<u32, SignatureKeyPair<Ed25519Signature>>> {
    TEST_AUTH_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn test_auth_key_pair(uid: u32) -> SignatureKeyPair<Ed25519Signature> {
    let mut keys = test_auth_keys().lock().unwrap();
    keys.entry(uid)
        .or_insert_with(SignatureKeyPair::<Ed25519Signature>::new)
        .clone()
}

pub fn test_auth_key_string(uid: u32) -> String {
    let key_pair = test_auth_key_pair(uid);
    let json_bytes = serde_json::to_vec(key_pair.verification_key()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(json_bytes)
}

pub fn sign_test_change(uid: u32, change: &mut Change) {
    let key_pair = test_auth_key_pair(uid);
    sign_change(&mut change.entry, &key_pair);
}

/// Returns the "products" schema used across changelog tests.
pub fn products_schema() -> Schema {
    Schema {
        name: "products".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: ColumnType::String,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "price".to_string(),
                column_type: ColumnType::Real,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

/// Returns the "_users" system table schema.
/// Must match the canonical definition in backend/src/internal_schemas.kdl.
pub fn users_schema() -> Schema {
    Schema {
        name: "_users".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "update_key".to_string(),
                column_type: ColumnType::Blob,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "auth_key".to_string(),
                column_type: ColumnType::Blob,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "status".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

/// Initialise a `SpaceState` with the products and _users schemas, optionally
/// inserting user rows and setting the FF-proof batch size.
///
/// This is the shared setup used by both `TestServer` and the integration tests
/// in `experiments/ff_test`.
pub async fn init_test_server_state(batch_size: Option<usize>, user_uids: &[u32]) -> SpaceState {
    init_test_server_state_with_schema(batch_size, user_uids, vec![products_schema()]).await
}

/// Initialize a test server with custom schemas and users.
pub async fn init_test_server_state_with_schema(
    batch_size: Option<usize>,
    user_uids: &[u32],
    schemas: Vec<Schema>,
) -> SpaceState {
    let init_cfg = SpaceInitConfig {
        space_id: SpaceId::from([0u8; 16]),
        artifact_path: None,
        verbose_logfile: None,
        bootstrap_data: BootstrapDataSource::None,
    };

    let mut all_schemas = schemas;
    all_schemas.push(users_schema());

    let mut state = SpaceState::init_server(Some(&all_schemas), Some(init_cfg), batch_size)
        .await
        .unwrap();

    let setup_auth = AuthContext::new(None, SpaceId::from([0u8; 16]));
    for &uid in user_uids {
        let user_insert = user_registration_query(uid);
        state.db.insert(user_insert, &setup_auth).await.unwrap();
    }

    // Re-initialize the changelog so the hash chain starting link matches
    // the current Merk root (after setup inserts).
    let root = state.get_root_hash().await;
    state.changelog = ChangeLog::new(&root);
    // Mirror `reinitialize_changelog`: keep the per-user sigref view
    // coupled to the changelog reset. Harmless today (setup goes through
    // `state.db.insert` directly, not `handle_change`, so the map is
    // already empty), but keeps the invariant from rotting if anyone
    // later routes setup through the tracked-change path.
    state.sigref_map.clear();

    state
}

/// Build the insert query to register a user in the `_users` table.
///
/// `uid` is informational only (used to derive the test auth key); the
/// actual row id comes from the auto-increment counter, which callers
/// align with by seeding users in uid order starting at 1.
pub fn user_registration_query(uid: u32) -> Query {
    Query::new(
        "_users".to_string(),
        QueryOperation::Insert(vec![
            ("update_key".to_string(), QueryParam::Text(String::new())),
            (
                "auth_key".to_string(),
                QueryParam::Text(test_auth_key_string(uid)),
            ),
            ("status".to_string(), QueryParam::Integer(1)), // Full member
        ]),
    )
}

/// A mixed table (Integer + Text + List + PieceText) used by the PieceText
/// fast-forward / prover fixtures.
pub fn mixed_docs_schema() -> Schema {
    Schema {
        name: "docs".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "title".to_string(),
                column_type: ColumnType::Text,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "items".to_string(),
                column_type: ColumnType::List,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "body".to_string(),
                column_type: ColumnType::PieceText,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: false,
    }
}

/// Identifies a PieceText parent cell in fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PieceTextFixtureAddress {
    pub table: String,
    pub row_id: i64,
    pub column: String,
}

/// Read a stored integer cell `(table, row_id, column)` from server state.
pub fn read_i64_cell(state: &SpaceState, table: &str, row_id: i64, column: &str) -> i64 {
    let bytes = state
        .db
        .get_value(&column_key(table, row_id, column))
        .unwrap()
        .unwrap_or_else(|| panic!("missing cell {table}.{column} at row {row_id}"));
    bytes_to_value(&bytes).unwrap().as_i64().unwrap()
}

fn stored_json(value: serde_json::Value) -> Vec<u8> {
    value_to_bytes(&value).expect("test stored value serialization")
}

fn put_test_key_value(state: &mut SpaceState, key: Vec<u8>, value: Vec<u8>) {
    state
        .db
        .apply_batch_ops(vec![(key, Op::Put(value))])
        .unwrap();
}

/// Insert a `docs` row with a list column and a PieceText parent cell, then
/// seed the PieceText head/tail/parent metadata so edits can be applied.
pub async fn prepare_piece_text_docs_setup(
    state: &mut SpaceState,
) -> (i64, PieceTextFixtureAddress) {
    let setup_auth = AuthContext::new(None, state.space_id);
    let row_id = 1i64;
    state
        .db
        .insert(
            Query::new(
                "docs".to_string(),
                QueryOperation::Insert(vec![
                    ("id".to_string(), QueryParam::Integer(row_id)),
                    ("title".to_string(), QueryParam::Text("doc".to_string())),
                    ("items".to_string(), QueryParam::Integer(0)),
                    ("body".to_string(), QueryParam::Integer(0)),
                ]),
            ),
            &setup_auth,
        )
        .await
        .unwrap();

    let items_list_number = read_i64_cell(state, "docs", row_id, "items");
    put_test_key_value(
        state,
        list_parent_key(items_list_number),
        encode_list_parent("docs", row_id, "items"),
    );

    let address = PieceTextFixtureAddress {
        table: "docs".to_string(),
        row_id,
        column: "body".to_string(),
    };

    let piece_text_list_number = 1i64;
    put_test_key_value(
        state,
        column_key(&address.table, address.row_id, &address.column),
        stored_json(serde_json::json!(piece_text_list_number)),
    );
    put_test_key_value(
        state,
        piece_coords_head_key(piece_text_list_number),
        0i64.to_be_bytes().to_vec(),
    );
    put_test_key_value(
        state,
        piece_coords_tail_key(piece_text_list_number),
        0i64.to_be_bytes().to_vec(),
    );
    put_test_key_value(
        state,
        piece_coords_parent_key(piece_text_list_number),
        encode_list_parent(&address.table, address.row_id, &address.column),
    );
    put_test_key_value(
        state,
        piece_coords_next_list_number_key(),
        (piece_text_list_number + 1).to_be_bytes().to_vec(),
    );

    (items_list_number, address)
}

/// Re-start the changelog at the post-setup root and refresh the snapshot.
pub async fn reset_changelog_after_setup(state: &mut SpaceState) -> merk::Node {
    state.reinitialize_changelog().await.unwrap();
    state.ff_proof = None;
    state.tree_snapshot = state.db.snapshot();
    state
        .tree_snapshot
        .clone()
        .expect("setup tree snapshot should exist")
}

/// Convert a fixture address into the verifier's `PieceTextAddress`.
fn piece_text_address(addr: &PieceTextFixtureAddress) -> PieceTextAddress {
    PieceTextAddress {
        table: addr.table.clone(),
        row_id: addr.row_id,
        column: addr.column.clone(),
    }
}

/// Content-address hash for a hash-backed value.
fn content_value_hash(body: &[u8]) -> [u8; 32] {
    encrypted_spaces_storage_encoding::hashstore_hash(body)
}

/// Build, sign, and apply a `Change` through `handle_change`.
async fn submit_signed_change(
    state: &mut SpaceState,
    auth: &AuthContext,
    op_type: OpType,
    keys: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
    hashed_values: HashedValues,
) {
    let uid = auth.uid.unwrap() as u32;
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();
    let cc = state.changelog.num_changes();
    let mut change = Change::new(
        op_type,
        uid,
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        cc,
        cc,
        state.changelog.current_root(),
    )
    .unwrap();
    change.hashed_values = hashed_values;
    sign_test_change(uid, &mut change);
    state.handle_change(&change, auth).await.unwrap();
}

/// Apply a normal product-table insert as a tracked change.
async fn submit_product_insert(state: &mut SpaceState, auth: &AuthContext, name: &str, price: f64) {
    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text(name.to_string())),
            ("price".to_string(), QueryParam::Real(price)),
        ]),
    );
    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    submit_signed_change(
        state,
        auth,
        OpType::Insert,
        col_keys,
        col_values,
        HashedValues::new(),
    )
    .await;
}

/// Apply a generic `_lists` append as a tracked change.
async fn submit_list_append(
    state: &mut SpaceState,
    auth: &AuthContext,
    list_number: i64,
    value: &str,
) {
    let full_value = value_to_bytes(&serde_json::Value::String(value.to_string())).unwrap();
    let value_hash = content_value_hash(&full_value);
    let keys = vec![
        column_key_placeholder("_lists", "list_number"),
        column_key_placeholder("_lists", "value"),
    ];
    let values = vec![
        value_to_bytes(&serde_json::json!(list_number)).unwrap(),
        value_hash.to_vec(),
    ];
    let mut hashed_values = HashedValues::new();
    hashed_values.insert(value_hash, full_value);
    submit_signed_change(state, auth, OpType::ListAppend, keys, values, hashed_values).await;
}

/// Apply an already-built `Change` directly through the native prover.
async fn apply_change_directly(state: &mut SpaceState, change: Change, current_change_id: usize) {
    let old_root = state.db.root_hash();
    let pruned_merkle_tree = state
        .db
        .apply_change_with_pruned_tree(&change, current_change_id)
        .await
        .unwrap();
    let new_root = state.db.root_hash();
    let change_id = state
        .changelog
        .add_change(&change.entry, &pruned_merkle_tree, &old_root, &new_root)
        .unwrap();
    state.change_responses.push(ChangeResponse {
        old_root,
        new_root,
        pruned_merkle_tree,
        change_id,
        rows_affected: 1,
        accepted_at_server_time: change.entry.timestamp,
        hashed_values: HashedValues::new(),
    });
}

/// Build, sign, and apply a `PieceTextEdit` change directly through the prover.
async fn submit_piece_text_edit(state: &mut SpaceState, auth: &AuthContext, message: LogMessage) {
    let uid = auth.uid.unwrap() as u32;
    let cc = state.changelog.num_changes();
    let current_change_id = cc as usize + 1;
    let entry = ChangelogEntry {
        timestamp: ChangelogEntry::get_unix_timestamp(),
        uid,
        parent_change: cc,
        message,
        sig_ref: cc,
        parent_clc: state.changelog.current_root(),
        signature: vec![],
    };
    let mut change = Change {
        entry,
        hashed_values: HashedValues::new(),
    };
    sign_test_change(uid, &mut change);
    apply_change_directly(state, change, current_change_id).await;
}

/// Append `text` at `at` as a single-insert `PieceTextEdit` (UTF-32LE bodies).
async fn submit_piece_text_append(
    state: &mut SpaceState,
    auth: &AuthContext,
    address: &PieceTextAddress,
    at: BufferCoord,
    text: &str,
    op_id_seed: u128,
) {
    let body: Vec<u8> = text
        .chars()
        .flat_map(|c| (c as u32).to_le_bytes())
        .collect();
    let envelope = PieceTextEditEnvelopeV1 {
        version: PIECE_TEXT_ENVELOPE_VERSION_V1,
        op_id: op_id_seed.to_be_bytes(),
        address: address.clone(),
        edit: PieceTextEditManifest {
            ops: vec![PieceTextEditItemManifest::Insert {
                at,
                inserted: InsertedBufferManifest {
                    len_bytes: body.len() as u32,
                    ciphertext_len: body.len() as u32,
                    ciphertext_value_hash: content_value_hash(&body),
                },
            }],
        },
    };
    submit_piece_text_edit(state, auth, envelope.changelog_message().unwrap()).await;
}

/// Tombstone the `[start, end)` span as a single-delete `PieceTextEdit`.
async fn submit_piece_text_delete(
    state: &mut SpaceState,
    auth: &AuthContext,
    address: &PieceTextAddress,
    start: BufferCoord,
    end: BufferCoord,
    op_id_seed: u128,
) {
    let envelope = PieceTextEditEnvelopeV1 {
        version: PIECE_TEXT_ENVELOPE_VERSION_V1,
        op_id: op_id_seed.to_be_bytes(),
        address: address.clone(),
        edit: PieceTextEditManifest {
            ops: vec![PieceTextEditItemManifest::Delete { start, end }],
        },
    };
    submit_piece_text_edit(state, auth, envelope.changelog_message().unwrap()).await;
}

/// Apply a system-source `PieceTextCleanupPieces` (uid 0) directly through the
/// prover. `op_id` is set to the current change id, as the verifier requires.
async fn submit_piece_text_cleanup_pieces(
    state: &mut SpaceState,
    address: &PieceTextAddress,
    list_number: i64,
    runs: Vec<PieceTextCleanupRunV1>,
) {
    let current_change_id = state.changelog.num_changes() as usize + 1;
    let envelope = PieceTextCleanupPiecesEnvelopeV1 {
        version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
        address: address.clone(),
        list_number,
        op_id: current_change_id as i64,
        runs,
    };
    apply_system_cleanup_change(
        state,
        envelope.changelog_message().unwrap(),
        current_change_id,
    )
    .await;
}

/// Apply a system-source `PieceTextCleanupBuffers` (uid 0) directly through the
/// prover. `op_id` is set to the current change id, as the verifier requires.
async fn submit_piece_text_cleanup_buffers(
    state: &mut SpaceState,
    address: &PieceTextAddress,
    buffer_removals: Vec<i64>,
) {
    let current_change_id = state.changelog.num_changes() as usize + 1;
    let envelope = PieceTextCleanupBuffersEnvelopeV1 {
        version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
        address: address.clone(),
        op_id: current_change_id as i64,
        buffer_removals,
    };
    apply_system_cleanup_change(
        state,
        envelope.changelog_message().unwrap(),
        current_change_id,
    )
    .await;
}

/// Build an unsigned system-source changelog entry (uid 0, sig_ref 0) for a
/// cleanup `LogMessage` and apply it through the native prover.
async fn apply_system_cleanup_change(
    state: &mut SpaceState,
    message: LogMessage,
    current_change_id: usize,
) {
    let entry = ChangelogEntry {
        timestamp: ChangelogEntry::get_unix_timestamp(),
        uid: 0,
        parent_change: state.changelog.num_changes(),
        message,
        sig_ref: 0,
        parent_clc: state.changelog.current_root(),
        signature: vec![],
    };
    let change = Change {
        entry,
        hashed_values: HashedValues::new(),
    };
    apply_change_directly(state, change, current_change_id).await;
}

/// Seed a fully-tombstoned `_piecetext_pieces` chain of `n_rows` rows (ids `1..=n`)
/// directly into the post-setup tree, every row referencing `buffer_id`, and
/// point the document head/tail at the chain ends. Used by the cleanup stress
/// fixture to build a worst-case (every row tombstoned) document without paying
/// for thousands of real `PieceTextEdit`s. Each row carries the seven
/// `_piecetext_pieces` columns plus its `list_number` and `buffer_id` index entries —
/// exactly what `PieceTextCleanupPieces` authenticates and deletes per row.
fn seed_tombstoned_piece_chain(
    state: &mut SpaceState,
    list_number: i64,
    buffer_id: i64,
    n_rows: i64,
) {
    const PIECE_LEN_BYTES: i64 = 4; // one UTF-32 scalar, satisfies alignment
    let mut ops: Vec<(Vec<u8>, Op)> = Vec::with_capacity(n_rows as usize * 9 + 2);
    for row_id in 1..=n_rows {
        let prev_id = if row_id == 1 { 0 } else { row_id - 1 };
        let next_id = if row_id == n_rows { 0 } else { row_id + 1 };
        let start_byte = (row_id - 1) * PIECE_LEN_BYTES;
        for (column, value) in [
            ("list_number", list_number),
            ("prev_id", prev_id),
            ("next_id", next_id),
            ("buffer_id", buffer_id),
            ("start_byte", start_byte),
            ("len_bytes", PIECE_LEN_BYTES),
            ("tombstone", 1),
        ] {
            ops.push((
                column_key(PIECE_COORDS_TABLE, row_id, column),
                Op::Put(stored_json(serde_json::json!(value))),
            ));
        }
        ops.push((
            index_key(PIECE_COORDS_TABLE, "list_number", list_number, row_id).unwrap(),
            Op::Put(row_id_to_bytes(row_id).to_vec()),
        ));
        ops.push((
            index_key(PIECE_COORDS_TABLE, "buffer_id", buffer_id, row_id).unwrap(),
            Op::Put(row_id_to_bytes(row_id).to_vec()),
        ));
    }
    ops.push((
        piece_coords_head_key(list_number),
        Op::Put(1i64.to_be_bytes().to_vec()),
    ));
    ops.push((
        piece_coords_tail_key(list_number),
        Op::Put(n_rows.to_be_bytes().to_vec()),
    ));
    state.db.apply_batch_ops(ops).unwrap();
}

/// Read a big-endian i64 stored directly under `key` (e.g. a head/tail pointer).
pub fn read_be_i64_key(state: &SpaceState, key: Vec<u8>) -> i64 {
    let bytes = state
        .db
        .get_value(&key)
        .unwrap()
        .unwrap_or_else(|| panic!("missing i64 key {key:?}"));
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes);
    i64::from_be_bytes(buf)
}

pub struct TestServer {
    state: SpaceState,
    /// Snapshot of the tree before changes were applied (needed for batch proof generation)
    tree_snapshot: Option<merk::Node>,
    /// The UID used for changelog entries in this test server
    user_uid: u32,
}

impl TestServer {
    pub fn changelog(&self) -> &ChangeLog {
        &self.state.changelog
    }
    pub fn responses(&self) -> &Vec<ChangeResponse> {
        &self.state.change_responses
    }
    pub fn tree_snapshot(&self) -> Option<&merk::Node> {
        self.tree_snapshot.as_ref()
    }
    /// Update the tree snapshot to the current state of the database.
    /// Call this after proving a batch to prepare for the next batch.
    pub fn update_tree_snapshot(&mut self) {
        self.tree_snapshot = self.state.db.snapshot();
    }

    /// A mixed history: a normal table insert, a generic `_lists` append, and
    /// two signed `PieceTextEdit` appends. Used to prove PieceTextEdit verifies
    /// through the FF core alongside other op types.
    pub async fn new_mixed_table_list_piece_text_history() -> Self {
        let mut state = init_test_server_state_with_schema(
            None,
            &[TEST_CLIENT_UID],
            vec![products_schema(), mixed_docs_schema()],
        )
        .await;
        let (items_list_number, fixture_address) = prepare_piece_text_docs_setup(&mut state).await;
        let address = piece_text_address(&fixture_address);
        let tree_snapshot = reset_changelog_after_setup(&mut state).await;
        let auth = AuthContext::new(Some(TEST_CLIENT_UID as i64), state.space_id);

        submit_product_insert(&mut state, &auth, "Mixed", 9.0).await;
        submit_list_append(&mut state, &auth, items_list_number, "item-1").await;
        submit_piece_text_append(
            &mut state,
            &auth,
            &address,
            BufferCoord::DOCUMENT_START,
            "one",
            1,
        )
        .await;
        submit_piece_text_append(
            &mut state,
            &auth,
            &address,
            BufferCoord {
                buffer_id: 1,
                byte_pos: 12, // 3 scalars × 4 UTF-32 bytes
            },
            "two",
            2,
        )
        .await;

        Self {
            state,
            tree_snapshot: Some(tree_snapshot),
            user_uid: TEST_CLIENT_UID,
        }
    }

    /// A mixed cleanup history exercising both split cleanup ops end to end:
    /// two signed `PieceTextEdit` appends ("alpha", then "beta"), a signed
    /// `PieceTextEdit` delete that tombstones the "alpha" piece, then a
    /// system-source `PieceTextCleanupPieces` that splices out the tombstoned
    /// row (head run, relinking the survivor as the new head) and finally a
    /// system-source `PieceTextCleanupBuffers` that deletes the now-orphaned
    /// "alpha" buffer once its `_piecetext_pieces.buffer_id` index range is empty.
    /// Used to prove a `PieceTextEdit` + `PieceTextCleanupPieces` +
    /// `PieceTextCleanupBuffers` history verifies through the FF core and that
    /// each cleanup op's per-change proof stays within budget.
    pub async fn new_piece_text_cleanup_history() -> Self {
        let mut state = init_test_server_state_with_schema(
            None,
            &[TEST_CLIENT_UID],
            vec![products_schema(), mixed_docs_schema()],
        )
        .await;
        let (_items_list_number, fixture_address) = prepare_piece_text_docs_setup(&mut state).await;
        let address = piece_text_address(&fixture_address);
        let tree_snapshot = reset_changelog_after_setup(&mut state).await;
        let auth = AuthContext::new(Some(TEST_CLIENT_UID as i64), state.space_id);

        // "alpha" (5 scalars → 20 UTF-32 bytes) lands in buffer 1 / piece P1.
        submit_piece_text_append(
            &mut state,
            &auth,
            &address,
            BufferCoord::DOCUMENT_START,
            "alpha",
            30_000,
        )
        .await;
        // "beta" appended at the end lands in buffer 2 / piece P2 (the survivor).
        submit_piece_text_append(
            &mut state,
            &auth,
            &address,
            BufferCoord {
                buffer_id: 1,
                byte_pos: 20,
            },
            "beta",
            30_001,
        )
        .await;

        let list_number = read_i64_cell(&state, &address.table, address.row_id, &address.column);
        let alpha_piece = read_be_i64_key(&state, piece_coords_head_key(list_number));
        let alpha_buffer = read_i64_cell(&state, PIECE_COORDS_TABLE, alpha_piece, "buffer_id");
        let alpha_len = read_i64_cell(&state, PIECE_COORDS_TABLE, alpha_piece, "len_bytes") as u32;

        // Tombstone the whole "alpha" span — a full-piece delete leaves P1 in the
        // chain (head, pointing at P2) with `tombstone = true`.
        submit_piece_text_delete(
            &mut state,
            &auth,
            &address,
            BufferCoord {
                buffer_id: alpha_buffer,
                byte_pos: 0,
            },
            BufferCoord {
                buffer_id: alpha_buffer,
                byte_pos: alpha_len,
            },
            30_002,
        )
        .await;

        // Piece cleanup: a single head run splices out P1 (prev_survivor 0 → list
        // head) and relinks P2 as the new head.
        submit_piece_text_cleanup_pieces(
            &mut state,
            &address,
            list_number,
            vec![PieceTextCleanupRunV1 {
                removals: vec![alpha_piece],
            }],
        )
        .await;

        // Buffer cleanup: "alpha"'s buffer is now unreferenced (P1 gone, P2 uses
        // buffer 2), so its `buffer_id` index range is empty and it is deletable.
        submit_piece_text_cleanup_buffers(&mut state, &address, vec![alpha_buffer]).await;

        Self {
            state,
            tree_snapshot: Some(tree_snapshot),
            user_uid: TEST_CLIENT_UID,
        }
    }

    /// A worst-case piece-cleanup stress history: a fully-tombstoned `n_rows`-row
    /// document drained by back-to-back `PieceTextCleanupPieces` chunks of up to
    /// `MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS` removals each. The synthetic chain
    /// is seeded into the pre-history tree, so the whole verified range is just
    /// the cleanup chunks. Every chunk removes a contiguous prefix run, so the
    /// optimized verifier touches only its own removed rows plus one boundary
    /// survivor — never the whole list. Used to measure that optimized cleanup
    /// `_piecetext_pieces` row visits stay far below the legacy
    /// whole-list-per-chunk shape.
    pub async fn new_piece_text_cleanup_pieces_stress_history(n_rows: usize) -> Self {
        let mut state = init_test_server_state_with_schema(
            None,
            &[TEST_CLIENT_UID],
            vec![products_schema(), mixed_docs_schema()],
        )
        .await;
        let (_items_list_number, fixture_address) = prepare_piece_text_docs_setup(&mut state).await;
        let address = piece_text_address(&fixture_address);
        let list_number = read_i64_cell(&state, &address.table, address.row_id, &address.column);
        let buffer_id = 1i64;
        let n = n_rows as i64;
        seed_tombstoned_piece_chain(&mut state, list_number, buffer_id, n);
        let tree_snapshot = reset_changelog_after_setup(&mut state).await;

        // Drain the chain from the front: each chunk removes the current head run
        // of up to the removal cap, relinking the next survivor as the new head
        // (or zeroing head/tail on the final remove-all chunk).
        let cap = MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS as i64;
        let mut start = 1i64;
        while start <= n {
            let end = (start + cap - 1).min(n);
            submit_piece_text_cleanup_pieces(
                &mut state,
                &address,
                list_number,
                vec![PieceTextCleanupRunV1 {
                    removals: (start..=end).collect(),
                }],
            )
            .await;
            start = end + 1;
        }

        Self {
            state,
            tree_snapshot: Some(tree_snapshot),
            user_uid: TEST_CLIENT_UID,
        }
    }

    /// Creates a new ChangeLog with the specified number of test changes.
    ///
    /// # Arguments
    /// * `length` - Number of changes to generate
    /// * `value_size` - Optional size (in bytes) for each change's value. When `Some(n)`,
    ///   the name field is padded so the serialized row is approximately `n` bytes.
    ///   When `None`, default test data (Apple/Banana/Cherry rows) is used.
    pub async fn new_for_tests(length: usize, value_size: Option<usize>) -> Self {
        Self::new_for_tests_impl(length, value_size, TEST_CLIENT_UID, true).await
    }

    /// Creates a new ChangeLog with the specified number of test changes and a custom user UID.
    /// The `_users` table will contain a row for this UID.
    ///
    /// # Arguments
    /// * `length` - Number of changes to generate
    /// * `value_size` - Optional size (in bytes) for each change's value.
    /// * `user_uid` - The UID to use for changelog entries. A matching row is inserted to `_users`.
    pub async fn new_for_tests_with_uid(
        length: usize,
        value_size: Option<usize>,
        user_uid: u32,
    ) -> Self {
        Self::new_for_tests_impl(length, value_size, user_uid, true).await
    }

    /// Creates a new ChangeLog where entries reference a user that does NOT exist in `_users`.
    /// This is used to test that proofs correctly reject unknown users.
    pub async fn new_for_tests_unknown_user(length: usize) -> Self {
        Self::new_for_tests_impl(length, None, TEST_CLIENT_UID, false).await
    }

    async fn new_for_tests_impl(
        length: usize,
        value_size: Option<usize>,
        user_uid: u32,
        insert_user_row: bool,
    ) -> Self {
        let user_uids: &[u32] = if insert_user_row { &[user_uid] } else { &[] };
        let mut state = init_test_server_state(None, user_uids).await;

        // Take initial tree snapshot before any changes are made
        let tree_snapshot = state.db.snapshot();

        let client_uid = user_uid;
        let auth1 = AuthContext::new(Some(client_uid as i64), SpaceId::from([0u8; 16]));
        let mut client_current_change_id = 0;
        let mut client_my_last_change_id = 0;

        // When a specific value_size is requested, build a padded name string so the
        // serialized row is approximately that many bytes. Otherwise use empty string
        // (the default test data names will be used instead).
        let padded_name: String = match value_size {
            Some(vs) => {
                let json_overhead = r#"{"name":"","price":2.0}"#.len();
                let name_len = if vs > json_overhead {
                    vs - json_overhead
                } else {
                    1
                };
                "X".repeat(name_len)
            }
            None => String::new(),
        };

        let test_rows: Vec<(i64, &str, f64)> = vec![
            (0, "Apple", 2.0),
            (0, "Banana", 1.5),
            (0, "Cherry", 3.0),
            (0, "Apple", 1.0),
            (0, "Banana", 2.5),
            (0, "Cherry", 3.2),
        ];

        let mut num_changes = 0;
        loop {
            for (id, name, price) in &test_rows {
                let actual_name = if padded_name.is_empty() {
                    name.to_string()
                } else {
                    padded_name.clone()
                };
                println!(
                    "Creating client change, insert (id, name, price) = ({id}, {}, {price})",
                    if padded_name.is_empty() {
                        name.to_string()
                    } else {
                        format!("[{}B padded]", padded_name.len())
                    }
                );

                let query = Query::new(
                    "products".to_string(),
                    QueryOperation::Insert(vec![
                        ("id".to_string(), QueryParam::Integer(*id)),
                        ("name".to_string(), QueryParam::Text(actual_name)),
                        ("price".to_string(), QueryParam::Real(*price)),
                    ]),
                );

                let (_, column_data) = get_row_data_from_query(&query).unwrap();
                let (col_keys, col_values) = build_column_kv_vecs(&column_data, |col| {
                    column_key_placeholder("products", col)
                });
                let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
                let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

                let mut change = Change::new(
                    OpType::Insert,
                    client_uid,
                    ROOT_TREE_PATH,
                    &key_refs,
                    &val_refs,
                    client_current_change_id,
                    client_my_last_change_id,
                    state.changelog.current_root(), // The current CLC
                )
                .unwrap();
                sign_test_change(client_uid, &mut change);

                let _response = state.handle_change(&change, &auth1).await;

                num_changes += 1;
                client_current_change_id += 1;
                client_my_last_change_id += 1;
                if num_changes == length {
                    return Self {
                        state,
                        tree_snapshot,
                        user_uid,
                    };
                }
            }
        }
    }

    pub async fn add_more_changes(&mut self, num_new_changes: usize) {
        let client_uid = self.user_uid;
        let auth1 = AuthContext::new(Some(client_uid as i64), SpaceId::from([0u8; 16]));
        let mut client_current_change_id = self.state.changelog.num_changes();
        let mut client_my_last_change_id = client_current_change_id;
        let mut num_changes = 0;

        loop {
            for (id, name, price) in &[
                (0, "Apple", 2.0),
                (0, "Banana", 1.5),
                (0, "Cherry", 3.0),
                (0, "Apple", 1.0),
                (0, "Banana", 2.5),
                (0, "Cherry", 3.2),
            ] {
                println!(
                    "Creating client change, insert (id, name, price) = ({id}, {name}, {price})"
                );

                let query = Query::new(
                    "products".to_string(),
                    QueryOperation::Insert(vec![
                        ("id".to_string(), QueryParam::Integer(*id)),
                        ("name".to_string(), QueryParam::Text(name.to_string())),
                        ("price".to_string(), QueryParam::Real(*price)),
                    ]),
                );

                let (_, column_data) = get_row_data_from_query(&query).unwrap();
                let (col_keys, col_values) = build_column_kv_vecs(&column_data, |col| {
                    column_key_placeholder("products", col)
                });
                let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
                let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

                let mut change = Change::new(
                    OpType::Insert,
                    client_uid,
                    ROOT_TREE_PATH,
                    &key_refs,
                    &val_refs,
                    client_current_change_id,
                    client_my_last_change_id,
                    self.state.changelog.current_root(), // Current CLC
                )
                .unwrap();
                sign_test_change(client_uid, &mut change);

                let _response = self.state.handle_change(&change, &auth1).await;

                num_changes += 1;
                client_current_change_id += 1;
                client_my_last_change_id += 1;
                if num_changes == num_new_changes {
                    return;
                }
            }
        }
    }

    /// Creates a new TestServer with interleaved changes from multiple users.
    /// The pattern repeats the user_uids slice, so [1,2] with length=5 gives: 1,2,1,2,1.
    /// Returns the TestServer along with the per-user last change_id map (for verification).
    pub async fn new_multi_user(length: usize, user_uids: &[u32]) -> (Self, HashMap<u32, u32>) {
        assert!(!user_uids.is_empty(), "need at least one user");

        let mut state = init_test_server_state(None, user_uids).await;
        let tree_snapshot = state.db.snapshot();

        // Track each user's last change_id for sigref
        let mut user_last_change: HashMap<u32, u32> = HashMap::new();
        let mut global_change_id: u32 = 0;

        let test_rows: Vec<(&str, f64)> = vec![
            ("Apple", 2.0),
            ("Banana", 1.5),
            ("Cherry", 3.0),
            ("Date", 1.0),
            ("Elderberry", 2.5),
            ("Fig", 3.2),
        ];

        for i in 0..length {
            let uid = user_uids[i % user_uids.len()];
            let auth = AuthContext::new(Some(uid as i64), SpaceId::from([0u8; 16]));
            let (name, price) = &test_rows[i % test_rows.len()];

            let query = Query::new(
                "products".to_string(),
                QueryOperation::Insert(vec![
                    ("id".to_string(), QueryParam::Integer(0)),
                    ("name".to_string(), QueryParam::Text(name.to_string())),
                    ("price".to_string(), QueryParam::Real(*price)),
                ]),
            );

            let (_, column_data) = get_row_data_from_query(&query).unwrap();
            let (col_keys, col_values) =
                build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
            let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
            let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

            let my_last = user_last_change.get(&uid).copied().unwrap_or(0);

            let mut change = Change::new(
                OpType::Insert,
                uid,
                ROOT_TREE_PATH,
                &key_refs,
                &val_refs,
                global_change_id,
                my_last,
                state.changelog.current_root(),
            )
            .unwrap();
            sign_test_change(uid, &mut change);

            let _response = state.handle_change(&change, &auth).await;

            global_change_id += 1;
            user_last_change.insert(uid, global_change_id); // change_ids are 1-based
        }

        let server = Self {
            state,
            tree_snapshot,
            user_uid: user_uids[0],
        };
        (server, user_last_change)
    }
}

/// Insert an ACL rule into the `_access_control` table and re-finalize the blob.
/// Call this after `init_test_server_state` and before creating changelog entries.
pub async fn insert_acl_rule(
    state: &mut SpaceState,
    resource_name: &str,
    operation: &str,
    rule_json: &str,
) {
    let auth = AuthContext::new(None, SpaceId::from([0u8; 16]));
    let query = Query::new(
        "_access_control".to_string(),
        QueryOperation::Insert(vec![
            (
                "resource_name".to_string(),
                QueryParam::Text(resource_name.to_string()),
            ),
            (
                "operation".to_string(),
                QueryParam::Text(operation.to_string()),
            ),
            (
                "rule_json".to_string(),
                QueryParam::Text(rule_json.to_string()),
            ),
        ]),
    );
    state.db.insert(query, &auth).await.unwrap();
    // Re-finalize the ACL blob so the new rule is visible to the verifier
    state.db.finalize_acl_blob().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify ACL blob round-trip: write via finalize_acl_blob, read back, deserialize.
    #[tokio::test]
    async fn acl_rule_round_trip() {
        let mut state = init_test_server_state(None, &[TEST_CLIENT_UID]).await;

        // Initially no rule for (products, write).
        let initial = state
            .db
            .read_acl_rule("products", "write")
            .expect("read_acl_rule");
        assert!(initial.is_none(), "expected no rule, got: {initial:?}");

        // Insert a rule and re-finalize. The rule must reference an Integer
        // column that exists in the target table — `finalize_acl_blob` lints
        // both. `products.id` satisfies both constraints.
        insert_acl_rule(
            &mut state,
            "products",
            "write",
            r#"{"Comparison":{"left":{"Column":{"namespace":"Resource","name":"id"}},"op":"Equal","right":"AuthUserId"}}"#,
        )
        .await;

        let rule = state
            .db
            .read_acl_rule("products", "write")
            .expect("read_acl_rule");
        assert!(rule.is_some(), "expected rule, got: {rule:?}");
    }
}
