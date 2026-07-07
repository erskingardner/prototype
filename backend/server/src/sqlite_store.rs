use crate::db::{ServerError, SpaceState};
use crate::durable_store::{DurableSpaceStateStore, LoadedSpaceState};
use crate::key_delivery::GroupKeyDeliverySlots;
use encrypted_spaces_backend::merk_storage::{FlatMerkEntries, MerkStorage};
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_changelog_core::changelog::{ChangeLog, ChangeResponse};
use encrypted_spaces_ffproof::common::FFProof;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SQLITE_SCHEMA_VERSION: i64 = 1;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct SqliteSpaceStore {
    artifact_dir: PathBuf,
    db_path: PathBuf,
}

#[derive(Debug)]
struct PersistedMeta {
    version: i64,
    space_id: Vec<u8>,
    root_hash: Vec<u8>,
    changelog: Vec<u8>,
    change_responses: Vec<u8>,
    sigref_map: Vec<u8>,
    hash_store: Vec<u8>,
    key_delivery_slots: Vec<u8>,
}

impl SqliteSpaceStore {
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        let artifact_dir = artifact_dir.into();
        let db_path = artifact_dir.join("db.sqlite3");
        Self {
            artifact_dir,
            db_path,
        }
    }

    #[cfg(test)]
    pub(crate) fn db_path(&self) -> &std::path::Path {
        &self.db_path
    }
}

impl DurableSpaceStateStore for SqliteSpaceStore {
    fn state_exists(&self) -> bool {
        self.db_path.exists()
    }

    fn save(&self, state: &SpaceState) -> Result<(), ServerError> {
        fs::create_dir_all(&self.artifact_dir).map_err(|e| {
            ServerError::Generic(format!(
                "sqlite store: failed to create artifact directory '{}': {e}",
                self.artifact_dir.display()
            ))
        })?;
        fs::create_dir_all(self.artifact_dir.join("files")).map_err(|e| {
            ServerError::Generic(format!(
                "sqlite store: failed to create files directory for '{}': {e}",
                self.artifact_dir.display()
            ))
        })?;

        let mut conn = self.open()?;
        Self::initialize_schema(&conn)?;

        let root_hash = state.db.root_hash();
        let merk_entries = state.db.export_entries().map_err(ServerError::from)?;
        let changelog = state.changelog.as_bytes();
        let change_responses = ChangeResponse::to_bytes(&state.change_responses);
        let sigref_map = postcard::to_allocvec(&state.sigref_map).map_err(|e| {
            ServerError::Generic(format!("sqlite store: failed to serialize sigref_map: {e}"))
        })?;
        let hash_store = postcard::to_allocvec(&state.hash_store).map_err(|e| {
            ServerError::Generic(format!("sqlite store: failed to serialize hash_store: {e}"))
        })?;
        let key_delivery_slots = postcard::to_allocvec(&state.key_delivery_slots).map_err(|e| {
            ServerError::Generic(format!(
                "sqlite store: failed to serialize key_delivery_slots: {e}"
            ))
        })?;

        let now = unix_timestamp()?;
        let tx = conn.transaction().map_err(sqlite_error)?;
        let created_at = tx
            .query_row(
                "SELECT created_at FROM space_meta WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .unwrap_or(now);

        tx.execute("DELETE FROM merk_entries", [])
            .map_err(sqlite_error)?;
        tx.execute("DELETE FROM ff_batch_base_entries", [])
            .map_err(sqlite_error)?;
        tx.execute("DELETE FROM space_meta WHERE id = 1", [])
            .map_err(sqlite_error)?;

        tx.execute(
            "INSERT INTO space_meta (
                id,
                version,
                space_id,
                root_hash,
                changelog,
                change_responses,
                sigref_map,
                hash_store,
                key_delivery_slots,
                created_at,
                updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                SQLITE_SCHEMA_VERSION,
                state.space_id.as_bytes().as_slice(),
                root_hash.as_slice(),
                changelog.as_slice(),
                change_responses.as_slice(),
                sigref_map.as_slice(),
                hash_store.as_slice(),
                key_delivery_slots.as_slice(),
                created_at,
                now,
            ],
        )
        .map_err(sqlite_error)?;

        {
            let mut stmt = tx
                .prepare("INSERT INTO merk_entries (position, key, value) VALUES (?1, ?2, ?3)")
                .map_err(sqlite_error)?;
            // Preserve export order: MerkStorage replays these entries one at a
            // time, and that order preserves the authenticated tree shape.
            for (position, (key, value)) in merk_entries.iter().enumerate() {
                stmt.execute(params![
                    entry_position(position)?,
                    key.as_slice(),
                    value.as_slice()
                ])
                .map_err(sqlite_error)?;
            }
        }

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO ff_batch_base_entries (position, key, value) VALUES (?1, ?2, ?3)",
                )
                .map_err(sqlite_error)?;
            for (position, (key, value)) in state.tree_snapshot_entries.iter().enumerate() {
                stmt.execute(params![
                    entry_position(position)?,
                    key.as_slice(),
                    value.as_slice()
                ])
                .map_err(sqlite_error)?;
            }
        }

        tx.commit().map_err(sqlite_error)
    }

    fn load(&self, expected_space_id: SpaceId) -> Result<Option<LoadedSpaceState>, ServerError> {
        if !self.db_path.exists() {
            return Ok(None);
        }

        let conn = self.open()?;
        let user_version = conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?;
        if user_version != SQLITE_SCHEMA_VERSION {
            return Err(ServerError::Generic(format!(
                "sqlite store: unsupported schema user_version {user_version}, expected {SQLITE_SCHEMA_VERSION}"
            )));
        }

        let meta = conn
            .query_row(
                "SELECT
                    version,
                    space_id,
                    root_hash,
                    changelog,
                    change_responses,
                    sigref_map,
                    hash_store,
                    key_delivery_slots
                 FROM space_meta
                 WHERE id = 1",
                [],
                |row| {
                    Ok(PersistedMeta {
                        version: row.get(0)?,
                        space_id: row.get(1)?,
                        root_hash: row.get(2)?,
                        changelog: row.get(3)?,
                        change_responses: row.get(4)?,
                        sigref_map: row.get(5)?,
                        hash_store: row.get(6)?,
                        key_delivery_slots: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| {
                ServerError::Generic(format!(
                    "sqlite store '{}' exists but has no space_meta row",
                    self.db_path.display()
                ))
            })?;

        if meta.version != SQLITE_SCHEMA_VERSION {
            return Err(ServerError::Generic(format!(
                "sqlite store: unsupported metadata version {}, expected {SQLITE_SCHEMA_VERSION}",
                meta.version
            )));
        }

        let stored_space_id = SpaceId::try_from(meta.space_id.as_slice()).map_err(|e| {
            ServerError::Generic(format!("sqlite store: invalid stored space_id: {e}"))
        })?;
        if stored_space_id != expected_space_id {
            return Err(ServerError::Generic(format!(
                "sqlite store: space_id mismatch, expected {expected_space_id}, found {stored_space_id}"
            )));
        }

        let stored_root_hash: [u8; 32] = meta.root_hash.as_slice().try_into().map_err(|_| {
            ServerError::Generic(format!(
                "sqlite store: root_hash has {} bytes, expected 32",
                meta.root_hash.len()
            ))
        })?;
        let merk_entries = Self::load_entries(&conn, "merk_entries")?;
        let db = MerkStorage::from_entries(merk_entries).map_err(ServerError::from)?;
        let rebuilt_root = db.root_hash();
        if rebuilt_root != stored_root_hash {
            return Err(ServerError::Generic(format!(
                "sqlite store: root hash mismatch, metadata={} rebuilt={}",
                hex::encode(stored_root_hash),
                hex::encode(rebuilt_root)
            )));
        }

        let changelog = ChangeLog::from_bytes(&meta.changelog).map_err(ServerError::from)?;
        let change_responses = ChangeResponse::from_bytes(&meta.change_responses)
            .map_err(|e| ServerError::Generic(format!("sqlite store: {e}")))?;
        if change_responses.len() != changelog.changes.len() {
            return Err(ServerError::Generic(format!(
                "sqlite store: change_responses length {} does not match changelog length {}",
                change_responses.len(),
                changelog.changes.len()
            )));
        }
        validate_data_root_chain(&changelog, &change_responses, &rebuilt_root)?;

        let sigref_map =
            postcard::from_bytes::<BTreeMap<u32, u32>>(&meta.sigref_map).map_err(|e| {
                ServerError::Generic(format!(
                    "sqlite store: failed to deserialize sigref_map: {e}"
                ))
            })?;
        let hash_store = postcard::from_bytes::<HashMap<[u8; 32], Vec<u8>>>(&meta.hash_store)
            .map_err(|e| {
                ServerError::Generic(format!(
                    "sqlite store: failed to deserialize hash_store: {e}"
                ))
            })?;
        let key_delivery_slots = postcard::from_bytes::<GroupKeyDeliverySlots>(
            &meta.key_delivery_slots,
        )
        .map_err(|e| {
            ServerError::Generic(format!(
                "sqlite store: failed to deserialize key_delivery_slots: {e}"
            ))
        })?;

        let ff_proof = if changelog.ff_proof.is_empty() {
            None
        } else {
            Some(FFProof::deserialize(&changelog.ff_proof).map_err(|e| {
                ServerError::Generic(format!("sqlite store: failed to deserialize FF proof: {e}"))
            })?)
        };

        let tree_snapshot_entries = Self::load_entries(&conn, "ff_batch_base_entries")?;
        let snapshot_db =
            MerkStorage::from_entries(tree_snapshot_entries.clone()).map_err(ServerError::from)?;
        let snapshot_root = snapshot_db.root_hash();
        let expected_snapshot_root =
            expected_tree_snapshot_root(&changelog, &change_responses, &rebuilt_root)?;
        if snapshot_root != expected_snapshot_root {
            return Err(ServerError::Generic(format!(
                "sqlite store: FF batch snapshot root mismatch, expected={} rebuilt={}",
                hex::encode(expected_snapshot_root),
                hex::encode(snapshot_root)
            )));
        }
        let tree_snapshot = snapshot_db.snapshot();

        Ok(Some(LoadedSpaceState {
            db,
            changelog,
            change_responses,
            ff_proof,
            tree_snapshot,
            tree_snapshot_entries,
            sigref_map,
            hash_store,
            key_delivery_slots,
        }))
    }
}

impl SqliteSpaceStore {
    fn open(&self) -> Result<Connection, ServerError> {
        let conn = Connection::open(&self.db_path).map_err(sqlite_error)?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
            .map_err(sqlite_error)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            ",
        )
        .map_err(sqlite_error)?;
        Ok(conn)
    }

    fn initialize_schema(conn: &Connection) -> Result<(), ServerError> {
        conn.execute_batch(
            "
            PRAGMA user_version = 1;

            CREATE TABLE IF NOT EXISTS space_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                space_id BLOB NOT NULL,
                root_hash BLOB NOT NULL,
                changelog BLOB NOT NULL,
                change_responses BLOB NOT NULL,
                sigref_map BLOB NOT NULL,
                hash_store BLOB NOT NULL,
                key_delivery_slots BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS merk_entries (
                position INTEGER NOT NULL UNIQUE,
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ff_batch_base_entries (
                position INTEGER NOT NULL UNIQUE,
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            );
            ",
        )
        .map_err(sqlite_error)
    }

    fn load_entries(
        conn: &Connection,
        table_name: &'static str,
    ) -> Result<FlatMerkEntries, ServerError> {
        // Rebuild in the exact export order saved by `save`; sorted key order
        // can rebuild a different valid tree shape with a different root hash.
        let sql = format!("SELECT key, value FROM {table_name} ORDER BY position");
        let mut stmt = conn.prepare(&sql).map_err(sqlite_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(sqlite_error)?);
        }
        Ok(entries)
    }
}

fn unix_timestamp() -> Result<i64, ServerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
        ServerError::Generic(format!("sqlite store: system clock before unix epoch: {e}"))
    })?;
    i64::try_from(duration.as_secs())
        .map_err(|_| ServerError::Generic("sqlite store: unix timestamp exceeds i64".to_string()))
}

fn entry_position(position: usize) -> Result<i64, ServerError> {
    i64::try_from(position).map_err(|_| {
        ServerError::Generic("sqlite store: entry position exceeds i64 range".to_string())
    })
}

fn sqlite_error(error: rusqlite::Error) -> ServerError {
    ServerError::Generic(format!("sqlite store: {error}"))
}

fn validate_data_root_chain(
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    db_root: &[u8; 32],
) -> Result<(), ServerError> {
    let mut expected_old_root = changelog.initial_dc;
    for (idx, response) in change_responses.iter().enumerate() {
        let expected_change_id = u32::try_from(idx + 1)
            .map_err(|_| ServerError::Generic("sqlite store: change_id exceeds u32".to_string()))?;
        if response.change_id != expected_change_id {
            return Err(ServerError::Generic(format!(
                "sqlite store: change_response at index {idx} has change_id {}, expected {expected_change_id}",
                response.change_id
            )));
        }
        if response.old_root != expected_old_root {
            return Err(ServerError::Generic(format!(
                "sqlite store: change_response {expected_change_id} old_root mismatch, expected={} found={}",
                hex::encode(expected_old_root),
                hex::encode(response.old_root)
            )));
        }
        expected_old_root = response.new_root;
    }

    if expected_old_root != *db_root {
        return Err(ServerError::Generic(format!(
            "sqlite store: changelog data root mismatch, responses={} db={}",
            hex::encode(expected_old_root),
            hex::encode(db_root)
        )));
    }

    Ok(())
}

fn expected_tree_snapshot_root(
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    db_root: &[u8; 32],
) -> Result<[u8; 32], ServerError> {
    if changelog.proven_up_to > change_responses.len() {
        return Err(ServerError::Generic(format!(
            "sqlite store: proven_up_to {} exceeds change_responses length {}",
            changelog.proven_up_to,
            change_responses.len()
        )));
    }

    if changelog.proven_up_to < change_responses.len() {
        Ok(change_responses[changelog.proven_up_to].old_root)
    } else {
        Ok(*db_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_config::{BootstrapDataSource, SpaceInitConfig};
    use encrypted_spaces_backend::merk_storage::Op;

    fn temp_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "encrypted_spaces_sqlite_{test_name}_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn test_state(space_id: SpaceId) -> SpaceState {
        SpaceState::init_server(
            None,
            Some(SpaceInitConfig {
                space_id,
                artifact_path: None,
                verbose_logfile: None,
                bootstrap_data: BootstrapDataSource::None,
            }),
            None,
        )
        .await
        .unwrap()
    }

    #[test]
    fn load_missing_space_returns_none() {
        let dir = temp_dir("missing");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let loaded = store.load(SpaceId::random()).unwrap();
        assert!(loaded.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn save_creates_per_space_db_and_schema() {
        let dir = temp_dir("schema");
        let artifact_dir = dir.join("space");
        let store = SqliteSpaceStore::new(&artifact_dir);
        let state = test_state(SpaceId::random()).await;

        store.save(&state).unwrap();

        assert!(artifact_dir.join("db.sqlite3").exists());
        assert!(artifact_dir.join("files").is_dir());

        let conn = Connection::open(store.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, SQLITE_SCHEMA_VERSION);

        for table in ["space_meta", "merk_entries", "ff_batch_base_entries"] {
            let found: String = conn
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(found, table);
        }

        for table in ["merk_entries", "ff_batch_base_entries"] {
            let found: String = conn
                .query_row(
                    "SELECT name FROM pragma_table_info(?1) WHERE name = 'position'",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(found, "position");
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn save_load_roundtrips_persisted_fields() {
        let dir = temp_dir("roundtrip");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let mut state = test_state(SpaceId::random()).await;

        state
            .db
            .apply_batch_ops(vec![(b"custom:key".to_vec(), Op::Put(b"value".to_vec()))])
            .unwrap();
        state.reinitialize_changelog().await.unwrap();
        state.sigref_map.insert(7, 3);
        state.hash_store.insert([0xAB; 32], b"full value".to_vec());
        state.key_delivery_slots.put(42, b"invite slot".to_vec());
        state.tree_snapshot_entries = state.db.export_entries().unwrap();
        state.tree_snapshot = state.db.snapshot();

        store.save(&state).unwrap();
        let loaded = store.load(state.space_id).unwrap().unwrap();

        assert_eq!(loaded.db.root_hash(), state.db.root_hash());
        assert_eq!(
            loaded.db.get_value(b"custom:key").unwrap(),
            Some(b"value".to_vec())
        );
        assert_eq!(loaded.changelog.as_bytes(), state.changelog.as_bytes());
        assert_eq!(loaded.change_responses.len(), state.change_responses.len());
        assert_eq!(loaded.sigref_map, state.sigref_map);
        assert_eq!(loaded.hash_store, state.hash_store);
        assert_eq!(
            loaded.key_delivery_slots.get(42).as_deref(),
            Some(&b"invite slot"[..])
        );
        assert_eq!(loaded.tree_snapshot_entries, state.tree_snapshot_entries);
        assert!(loaded.tree_snapshot.is_some());

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn replacement_removes_stale_merk_and_ff_rows() {
        let dir = temp_dir("replacement");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let mut state = test_state(SpaceId::random()).await;
        let stale_key = b"custom:stale".to_vec();

        state
            .db
            .apply_batch_ops(vec![(stale_key.clone(), Op::Put(b"stale".to_vec()))])
            .unwrap();
        state.reinitialize_changelog().await.unwrap();
        state.tree_snapshot_entries = state.db.export_entries().unwrap();
        state.tree_snapshot = state.db.snapshot();
        store.save(&state).unwrap();

        state
            .db
            .apply_batch_ops(vec![(stale_key.clone(), Op::Delete)])
            .unwrap();
        state.reinitialize_changelog().await.unwrap();
        state.tree_snapshot_entries = state.db.export_entries().unwrap();
        state.tree_snapshot = state.db.snapshot();
        store.save(&state).unwrap();

        let loaded = store.load(state.space_id).unwrap().unwrap();
        assert_eq!(loaded.db.get_value(&stale_key).unwrap(), None);
        assert!(!loaded
            .tree_snapshot_entries
            .iter()
            .any(|(key, _)| key == &stale_key));
        assert!(loaded.tree_snapshot.is_some());

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restore_fails_on_wrong_space_id() {
        let dir = temp_dir("wrong_space");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let state = test_state(SpaceId::random()).await;
        store.save(&state).unwrap();

        let conn = Connection::open(store.db_path()).unwrap();
        conn.execute(
            "UPDATE space_meta SET space_id = ?1 WHERE id = 1",
            [vec![0xFFu8; SpaceId::LEN]],
        )
        .unwrap();

        let err = match store.load(state.space_id) {
            Err(err) => err,
            Ok(_) => panic!("restore should fail on wrong space_id"),
        };
        assert!(err.to_string().contains("space_id mismatch"), "{err}");

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restore_fails_on_wrong_root_hash() {
        let dir = temp_dir("wrong_root");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let state = test_state(SpaceId::random()).await;
        store.save(&state).unwrap();

        let conn = Connection::open(store.db_path()).unwrap();
        conn.execute(
            "UPDATE space_meta SET root_hash = ?1 WHERE id = 1",
            [vec![0xEEu8; 32]],
        )
        .unwrap();

        let err = match store.load(state.space_id) {
            Err(err) => err,
            Ok(_) => panic!("restore should fail on wrong root hash"),
        };
        assert!(err.to_string().contains("root hash mismatch"), "{err}");

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restore_fails_on_wrong_ff_snapshot_root() {
        let dir = temp_dir("wrong_snapshot");
        let store = SqliteSpaceStore::new(dir.join("space"));
        let state = test_state(SpaceId::random()).await;
        store.save(&state).unwrap();

        let conn = Connection::open(store.db_path()).unwrap();
        conn.execute("DELETE FROM ff_batch_base_entries", [])
            .unwrap();
        conn.execute(
            "INSERT INTO ff_batch_base_entries (position, key, value) VALUES (?1, ?2, ?3)",
            params![
                0i64,
                b"not-the-real-snapshot".as_slice(),
                b"value".as_slice()
            ],
        )
        .unwrap();

        let err = match store.load(state.space_id) {
            Err(err) => err,
            Ok(_) => panic!("restore should fail on wrong FF snapshot root"),
        };
        assert!(
            err.to_string().contains("FF batch snapshot root mismatch"),
            "{err}"
        );

        let _ = fs::remove_dir_all(dir);
    }
}
