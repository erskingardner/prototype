//! Stage T3 + T4 of `docs/native_ops_plans/PLAN_FS_TEST.md` — multi-user,
//! cold-read self-consistency and the harness `MoveLastInode` /
//! `DeleteLastInode` gap. `docs/native_ops_plans/PLAN_NATIVE_FS_TEST.md` extends
//! these same scenarios with native-write variants.
//!
//! These tests live in the harness crate because they need a [`World`] with two
//! actors sharing one transport:
//!
//! - **Cold-read variants** drive the filesystem write verbs as actor A, then
//!   sync and assert the read surface seen by actor B. B's cache is cold for A's
//!   writes until the sync, so this exercises the committed / KV path the
//!   cache-bypassing read ops will use, not A's warm cache (the single-space
//!   `files.rs` / `fs_test_model.rs` tests cover the warm path).
//! - **Multi-user** tests (`list_dir_resolves_author_name`,
//!   `non_author_can_mutate`, `removed_user_cannot_write`) pin behavior that
//!   only manifests with a second active/removed user.
//! - **Smoke scenarios** invoke the `MoveLastInode` / `DeleteLastInode` harness
//!   actions and read back across actors, closing the harness gap (those
//!   actions existed but were never exercised by a test).
//!
//! ## Backends (Stage T4)
//!
//! Each cold-read / multi-user scenario body is written once against the
//! [`FsScenarioBackend`] trait and run for all three [`FsBackend`]s:
//!
//! - `TableWrapper` — the data-driven `files` wrapper verbs (`create_folder`,
//!   `upload_files`, …), which stamp `Utc::now()` (window timestamps).
//! - `NativeTable` — the SDK native inode ops over the same `inodes` table,
//!   with caller-supplied exact timestamps.
//! - `Tree` — the relative-inode `files_tree` backend (Stage T1/T2), addressed
//!   by hierarchical [`FsHandle`]s instead of `i64` row ids.
//!
//! The two table arms drive an [`FsModel`] keyed by `i64`; the tree arm drives a
//! [`TreeFsModel`] keyed by `FsHandle`, where a move rebases the moved root and
//! every descendant handle. The trait abstracts over the id type and the
//! reference model so the scenario bodies are shared, per the plan's note that
//! `Tree` is not a drop-in third value of the table-only `FsWriteMode` toggle.
//! The tree arm never consults the table `inodes` reads as an oracle: it reads
//! through the Tauri-shaped `files_tree` helper path and compares to its own
//! independent model.
//!
//! Run with `RISC0_SKIP_BUILD=1 cargo nextest run -p
//! encrypted-spaces-demo-test-harness` (the harness sets `RISC0_DEV_MODE` itself).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use encrypted_spaces_demo::files::{self, PendingFile};
use encrypted_spaces_demo::files_tree::{self, FsHandle};
use encrypted_spaces_demo_test_harness::cold_read::{
    assert_matches_model, assert_tree_matches_model, CreateArgs, FsModel, TimeExpect,
    TreeCreateArgs, TreeFsModel, FOLDER_HASH_HEX,
};
use encrypted_spaces_demo_test_harness::{
    assert_cold_read, assert_tree_cold_read, two_actor_world, Action, Runner, Scenario, World,
};
use encrypted_spaces_sdk::{File, Space};

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Current wall-clock time in whole seconds since the Unix epoch — the same
/// quantity the `files` wrappers stamp via `Utc::now().timestamp()`, so a
/// before/after pair brackets the timestamp a wrapper write records.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn pending(name: &str, mime: &str, data: &[u8]) -> PendingFile {
    PendingFile {
        data: data.to_vec(),
        filename: name.to_string(),
        mime_type: mime.to_string(),
    }
}

/// Clone an actor's `Space` handle and uid out of the world without holding the
/// world borrow across the `.await`s that follow.
fn actor_handle(world: &World, name: &str) -> (Arc<Space>, i64) {
    let actor = world.actor(name).expect("actor exists");
    (actor.space.clone(), actor.user_id)
}

#[derive(Debug, Clone, Copy)]
enum FsWriteMode {
    Wrapper,
    Native,
}

/// Create a folder through the selected write backend and record it in the
/// model. Returns the new inode id.
async fn folder_recorded(
    mode: FsWriteMode,
    space: &Space,
    model: &mut FsModel,
    author_name: &str,
    uid: i64,
    parent: i64,
    name: &str,
) -> i64 {
    let (inode, ctime, mtime) = match mode {
        FsWriteMode::Wrapper => {
            let before = now_secs();
            let inode = files::create_folder(space, parent, uid, name)
                .await
                .expect("create_folder");
            let after = now_secs();
            (
                inode,
                TimeExpect::window(before, after),
                TimeExpect::window(before, after),
            )
        }
        FsWriteMode::Native => {
            let ts = now_secs();
            let file_hash = File::from_hash(FOLDER_HASH_HEX.to_string());
            let id = space
                .submit_add_inode_native(
                    parent,
                    uid,
                    name,
                    files::INODE_FOLDER,
                    0,
                    ts,
                    ts,
                    "",
                    file_hash.clone(),
                )
                .await
                .expect("submit_add_inode_native folder");
            (
                files::Inode {
                    id: Some(id),
                    parent_id: parent,
                    author_id: uid,
                    name: name.to_string(),
                    inode_type: files::INODE_FOLDER,
                    size: 0,
                    ctime: ts,
                    mtime: ts,
                    mime_type: String::new(),
                    file_hash,
                },
                TimeExpect::Exact(ts),
                TimeExpect::Exact(ts),
            )
        }
    };
    model.record_created(
        &inode,
        CreateArgs {
            parent,
            name,
            author: uid,
            author_name,
            inode_type: files::INODE_FOLDER,
            size: 0,
            mime: "",
            file_hash: Some(FOLDER_HASH_HEX),
            bytes: None,
            ctime,
            mtime,
        },
    );
    inode.id.expect("created folder has an id")
}

/// Upload one file through the selected write backend and record it in the
/// model. Returns the new inode id.
#[allow(clippy::too_many_arguments)]
async fn upload_recorded(
    mode: FsWriteMode,
    space: &Space,
    model: &mut FsModel,
    author_name: &str,
    uid: i64,
    parent: i64,
    name: &str,
    data: &[u8],
) -> i64 {
    let (inode, ctime, mtime) = match mode {
        FsWriteMode::Wrapper => {
            let before = now_secs();
            let mut created =
                files::upload_files(space, parent, uid, vec![pending(name, "text/plain", data)])
                    .await
                    .expect("upload_files");
            let after = now_secs();
            assert_eq!(created.len(), 1, "one file uploaded");
            (
                created.remove(0),
                TimeExpect::window(before, after),
                TimeExpect::window(before, after),
            )
        }
        FsWriteMode::Native => {
            let ts = now_secs();
            let file_hash = space
                .file()
                .upload(File::from_data(data.to_vec()))
                .await
                .expect("pre-upload native file");
            let id = space
                .submit_add_inode_native(
                    parent,
                    uid,
                    name,
                    files::INODE_FILE,
                    data.len() as i64,
                    ts,
                    ts,
                    "text/plain",
                    file_hash.clone(),
                )
                .await
                .expect("submit_add_inode_native file");
            (
                files::Inode {
                    id: Some(id),
                    parent_id: parent,
                    author_id: uid,
                    name: name.to_string(),
                    inode_type: files::INODE_FILE,
                    size: data.len() as i64,
                    ctime: ts,
                    mtime: ts,
                    mime_type: "text/plain".to_string(),
                    file_hash,
                },
                TimeExpect::Exact(ts),
                TimeExpect::Exact(ts),
            )
        }
    };
    model.record_created(
        &inode,
        CreateArgs {
            parent,
            name,
            author: uid,
            author_name,
            inode_type: files::INODE_FILE,
            size: data.len() as i64,
            mime: "text/plain",
            file_hash: None,
            bytes: Some(data.to_vec()),
            ctime,
            mtime,
        },
    );
    inode.id.expect("uploaded file has an id")
}

async fn rename_recorded(
    mode: FsWriteMode,
    space: &Space,
    model: &mut FsModel,
    id: i64,
    new_name: &str,
) {
    let mtime = match mode {
        FsWriteMode::Wrapper => {
            let before = now_secs();
            let ok = files::rename_inode(space, id, new_name)
                .await
                .expect("rename_inode");
            let after = now_secs();
            assert!(ok, "rename_inode({id}) should update one row");
            TimeExpect::window(before, after)
        }
        FsWriteMode::Native => {
            let ts = now_secs();
            let rows = space
                .submit_rename_inode_native(id, new_name, ts)
                .await
                .expect("submit_rename_inode_native");
            assert_eq!(
                rows, 1,
                "submit_rename_inode_native({id}) should update one row"
            );
            TimeExpect::Exact(ts)
        }
    };
    model.rename(id, new_name, mtime);
}

async fn move_recorded(
    mode: FsWriteMode,
    space: &Space,
    model: &mut FsModel,
    id: i64,
    new_parent: i64,
) {
    let mtime = match mode {
        FsWriteMode::Wrapper => {
            let before = now_secs();
            let ok = files::move_inode(space, id, new_parent)
                .await
                .expect("move_inode");
            let after = now_secs();
            assert!(ok, "move_inode({id}) should update one row");
            TimeExpect::window(before, after)
        }
        FsWriteMode::Native => {
            let ts = now_secs();
            let rows = space
                .submit_move_inode_native(id, new_parent, ts)
                .await
                .expect("submit_move_inode_native");
            assert_eq!(
                rows, 1,
                "submit_move_inode_native({id}) should update one row"
            );
            TimeExpect::Exact(ts)
        }
    };
    model.reparent(id, new_parent, mtime);
}

async fn delete_recorded(mode: FsWriteMode, space: &Space, model: &mut FsModel, id: i64) {
    match mode {
        FsWriteMode::Wrapper => {
            let ok = files::delete_inode_recursive(space, id)
                .await
                .expect("delete_inode_recursive");
            assert!(
                ok,
                "delete_inode_recursive({id}) should remove the root inode"
            );
        }
        FsWriteMode::Native => {
            let rows = space
                .submit_delete_inode_recursive_native(id)
                .await
                .expect("submit_delete_inode_recursive_native");
            assert!(
                rows > 0,
                "submit_delete_inode_recursive_native({id}) should remove at least one inode"
            );
        }
    }
    model.delete_recursive(id);
}

async fn removed_user_create_folder(
    space: &Space,
    uid: i64,
    mode: FsWriteMode,
) -> std::result::Result<(), String> {
    match mode {
        FsWriteMode::Wrapper => files::create_folder(space, 0, uid, "blocked")
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        FsWriteMode::Native => {
            let ts = now_secs();
            space
                .submit_add_inode_native(
                    0,
                    uid,
                    "blocked",
                    files::INODE_FOLDER,
                    0,
                    ts,
                    ts,
                    "",
                    File::from_hash(FOLDER_HASH_HEX.to_string()),
                )
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        }
    }
}

async fn removed_user_upload_file(
    space: &Space,
    uid: i64,
    mode: FsWriteMode,
) -> std::result::Result<(), String> {
    match mode {
        FsWriteMode::Wrapper => files::upload_files(
            space,
            0,
            uid,
            vec![pending("blocked.txt", "text/plain", b"x")],
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}")),
        FsWriteMode::Native => {
            let ts = now_secs();
            space
                .submit_add_inode_native(
                    0,
                    uid,
                    "blocked.txt",
                    files::INODE_FILE,
                    1,
                    ts,
                    ts,
                    "text/plain",
                    File::from_hash("ab".repeat(32)),
                )
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        }
    }
}

async fn removed_user_rename(
    space: &Space,
    target: i64,
    mode: FsWriteMode,
) -> std::result::Result<(), String> {
    match mode {
        FsWriteMode::Wrapper => files::rename_inode(space, target, "renamed-by-removed")
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        FsWriteMode::Native => space
            .submit_rename_inode_native(target, "renamed-by-removed", now_secs())
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
    }
}

async fn removed_user_move(
    space: &Space,
    target: i64,
    dest: i64,
    mode: FsWriteMode,
) -> std::result::Result<(), String> {
    match mode {
        FsWriteMode::Wrapper => files::move_inode(space, target, dest)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        FsWriteMode::Native => space
            .submit_move_inode_native(target, dest, now_secs())
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
    }
}

async fn removed_user_delete(
    space: &Space,
    target: i64,
    mode: FsWriteMode,
) -> std::result::Result<(), String> {
    match mode {
        FsWriteMode::Wrapper => files::delete_inode_recursive(space, target)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        FsWriteMode::Native => space
            .submit_delete_inode_recursive_native(target)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
    }
}

// ─── Backend abstraction (Stage T4) ──────────────────────────────────────────

/// The three filesystem backends the cold-read / multi-user scenarios run
/// against. The two table arms differ only in their write path (data-driven
/// wrapper verbs vs SDK native ops) and share the `i64`-keyed [`FsModel`]; the
/// `Tree` arm is a distinct id model ([`FsHandle`]) over the relative-inode
/// `files_tree` backend with its own [`TreeFsModel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsBackend {
    TableWrapper,
    NativeTable,
    Tree,
}

/// Backend + reference-model abstraction shared by every scenario body.
///
/// `Id` is the node address — `i64` for the table arms, [`FsHandle`] for the
/// tree arm. Each implementor owns its reference model and records every write
/// into it, so a body asserts the read surface against the model the same way
/// regardless of backend. This is the plan's "trait over backend + model" that
/// lets `Tree` share scenario bodies with the table arms even though it is not a
/// drop-in [`FsWriteMode`] value (its ids are hierarchical and a move rebases
/// the moved root and every descendant handle).
#[allow(async_fn_in_trait)]
trait FsScenarioBackend {
    /// Node address type (`i64` row id or hierarchical [`FsHandle`]).
    type Id: Clone + PartialEq + std::fmt::Debug;

    /// Which backend this is (used for failure-context labeling).
    fn kind(&self) -> FsBackend;

    /// The root directory id (`0` for the tables, `[]` for the tree).
    fn root(&self) -> Self::Id;

    /// Create a folder under `parent`, record it in the model, return its id.
    async fn create_folder(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: Self::Id,
        name: &str,
    ) -> Self::Id;

    /// Upload one file under `parent`, record it in the model, return its id.
    #[allow(clippy::too_many_arguments)]
    async fn upload_file(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: Self::Id,
        name: &str,
        data: &[u8],
    ) -> Self::Id;

    /// Rename `id` and record the rename in the model.
    async fn rename(&mut self, space: &Space, id: Self::Id, new_name: &str);

    /// Move `id` under `new_parent`, record it, and return the moved root's
    /// (possibly rebased) id. For the table arms this equals `id`; for the tree
    /// arm it is the new hierarchical handle.
    async fn move_to(&mut self, space: &Space, id: Self::Id, new_parent: Self::Id) -> Self::Id;

    /// Recursively delete `id` and record the cascade in the model.
    async fn delete(&mut self, space: &Space, id: Self::Id);

    /// Rebase a descendant id captured before a move of `old_root` → `new_root`.
    /// Identity for the table arms (ids are stable); prefix-swap for the tree.
    fn rebase(&self, id: Self::Id, old_root: &Self::Id, new_root: &Self::Id) -> Self::Id;

    /// List `parent`'s direct children as `(id, author_name)` pairs through the
    /// backend's own read path.
    async fn list_author_names(&self, space: &Space, parent: Self::Id) -> Vec<(Self::Id, String)>;

    /// Sync everyone, drop `reader`'s cache, and assert `reader`'s cold read
    /// surface agrees with the model.
    async fn check_cold_read(&self, world: &World, reader: &str);

    /// Assert `space`'s (warm) read surface agrees with the model.
    async fn check_warm(&self, space: &Space);

    // Removed-user write attempts — each must error for a removed user.
    async fn removed_user_create_folder(&self, space: &Space, uid: i64) -> Result<(), String>;
    async fn removed_user_upload_file(&self, space: &Space, uid: i64) -> Result<(), String>;
    async fn removed_user_rename(&self, space: &Space, target: Self::Id) -> Result<(), String>;
    async fn removed_user_move(
        &self,
        space: &Space,
        target: Self::Id,
        dest: Self::Id,
    ) -> Result<(), String>;
    async fn removed_user_delete(&self, space: &Space, target: Self::Id) -> Result<(), String>;
}

/// Table backend (`i64` ids + [`FsModel`]). Covers both `TableWrapper`
/// (data-driven verbs) and `NativeTable` (SDK native ops) through the inner
/// [`FsWriteMode`], delegating to the mode-dispatched `*_recorded` /
/// `removed_user_*` helpers above so the table write/read paths are untouched.
struct TableBackend {
    mode: FsWriteMode,
    model: FsModel,
}

impl TableBackend {
    fn wrapper() -> Self {
        Self {
            mode: FsWriteMode::Wrapper,
            model: FsModel::new(),
        }
    }

    fn native() -> Self {
        Self {
            mode: FsWriteMode::Native,
            model: FsModel::new(),
        }
    }
}

impl FsScenarioBackend for TableBackend {
    type Id = i64;

    fn kind(&self) -> FsBackend {
        match self.mode {
            FsWriteMode::Wrapper => FsBackend::TableWrapper,
            FsWriteMode::Native => FsBackend::NativeTable,
        }
    }

    fn root(&self) -> i64 {
        0
    }

    async fn create_folder(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: i64,
        name: &str,
    ) -> i64 {
        folder_recorded(
            self.mode,
            space,
            &mut self.model,
            author_name,
            uid,
            parent,
            name,
        )
        .await
    }

    async fn upload_file(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: i64,
        name: &str,
        data: &[u8],
    ) -> i64 {
        upload_recorded(
            self.mode,
            space,
            &mut self.model,
            author_name,
            uid,
            parent,
            name,
            data,
        )
        .await
    }

    async fn rename(&mut self, space: &Space, id: i64, new_name: &str) {
        rename_recorded(self.mode, space, &mut self.model, id, new_name).await;
    }

    async fn move_to(&mut self, space: &Space, id: i64, new_parent: i64) -> i64 {
        move_recorded(self.mode, space, &mut self.model, id, new_parent).await;
        // Table row ids are stable across a move.
        id
    }

    async fn delete(&mut self, space: &Space, id: i64) {
        delete_recorded(self.mode, space, &mut self.model, id).await;
    }

    fn rebase(&self, id: i64, _old_root: &i64, _new_root: &i64) -> i64 {
        // Table row ids are position-independent — a descendant id is unchanged
        // by an ancestor move.
        id
    }

    async fn list_author_names(&self, space: &Space, parent: i64) -> Vec<(i64, String)> {
        files::list_children(space, parent)
            .await
            .expect("list_children")
            .into_iter()
            .map(|entry| (entry.id.expect("listed inode has id"), entry.author_name))
            .collect()
    }

    async fn check_cold_read(&self, world: &World, reader: &str) {
        assert_cold_read(world, reader, &self.model)
            .await
            .unwrap_or_else(|e| panic!("[{:?}] cold read for `{reader}` failed: {e}", self.kind()));
    }

    async fn check_warm(&self, space: &Space) {
        assert_matches_model(space, &self.model).await;
    }

    async fn removed_user_create_folder(&self, space: &Space, uid: i64) -> Result<(), String> {
        removed_user_create_folder(space, uid, self.mode).await
    }

    async fn removed_user_upload_file(&self, space: &Space, uid: i64) -> Result<(), String> {
        removed_user_upload_file(space, uid, self.mode).await
    }

    async fn removed_user_rename(&self, space: &Space, target: i64) -> Result<(), String> {
        removed_user_rename(space, target, self.mode).await
    }

    async fn removed_user_move(&self, space: &Space, target: i64, dest: i64) -> Result<(), String> {
        removed_user_move(space, target, dest, self.mode).await
    }

    async fn removed_user_delete(&self, space: &Space, target: i64) -> Result<(), String> {
        removed_user_delete(space, target, self.mode).await
    }
}

/// Tree backend ([`FsHandle`] ids + [`TreeFsModel`]). Drives the Tauri-shaped
/// `files_tree` helper path (Stage T1/T2) and records into the handle-keyed
/// model (Stage T3). The tree create/rename/move helpers stamp `Utc::now()`
/// internally, so every timestamp is checked as a before/after window — like the
/// wrapper arm, never the native arm's exact values.
struct TreeBackend {
    model: TreeFsModel,
}

impl TreeBackend {
    fn new() -> Self {
        Self {
            model: TreeFsModel::new(),
        }
    }
}

impl FsScenarioBackend for TreeBackend {
    type Id = FsHandle;

    fn kind(&self) -> FsBackend {
        FsBackend::Tree
    }

    fn root(&self) -> FsHandle {
        FsHandle::root()
    }

    async fn create_folder(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: FsHandle,
        name: &str,
    ) -> FsHandle {
        let before = now_secs();
        let inode = files_tree::create_folder_tree(space, parent.clone(), uid, name)
            .await
            .expect("create_folder_tree");
        let after = now_secs();
        self.model
            .record_created(
                space,
                &inode,
                TreeCreateArgs {
                    parent,
                    name,
                    author: uid,
                    author_name,
                    inode_type: files::INODE_FOLDER,
                    size: 0,
                    mime: "",
                    file_hash: Some(FOLDER_HASH_HEX),
                    bytes: None,
                    ctime: TimeExpect::window(before, after),
                    mtime: TimeExpect::window(before, after),
                },
            )
            .await;
        inode.id
    }

    async fn upload_file(
        &mut self,
        space: &Space,
        author_name: &str,
        uid: i64,
        parent: FsHandle,
        name: &str,
        data: &[u8],
    ) -> FsHandle {
        let before = now_secs();
        let mut created = files_tree::upload_files_tree(
            space,
            parent.clone(),
            uid,
            vec![pending(name, "text/plain", data)],
        )
        .await
        .expect("upload_files_tree");
        let after = now_secs();
        assert_eq!(created.len(), 1, "one tree file uploaded");
        let inode = created.remove(0);
        self.model
            .record_created(
                space,
                &inode,
                TreeCreateArgs {
                    parent,
                    name,
                    author: uid,
                    author_name,
                    inode_type: files::INODE_FILE,
                    size: data.len() as i64,
                    mime: "text/plain",
                    file_hash: None,
                    bytes: Some(data.to_vec()),
                    ctime: TimeExpect::window(before, after),
                    mtime: TimeExpect::window(before, after),
                },
            )
            .await;
        inode.id
    }

    async fn rename(&mut self, space: &Space, id: FsHandle, new_name: &str) {
        let before = now_secs();
        let ok = files_tree::rename_inode_tree(space, id.clone(), new_name)
            .await
            .expect("rename_inode_tree");
        let after = now_secs();
        assert!(ok, "rename_inode_tree({id:?}) should update one node");
        self.model
            .rename(&id, new_name, TimeExpect::window(before, after));
    }

    async fn move_to(&mut self, space: &Space, id: FsHandle, new_parent: FsHandle) -> FsHandle {
        let before = now_secs();
        let result = files_tree::move_inode_tree(space, id.clone(), new_parent)
            .await
            .expect("move_inode_tree");
        let after = now_secs();
        assert!(result.moved, "move_inode_tree({id:?}) should report moved");
        let new_id = result
            .new_id
            .expect("move must return the rebased root handle");
        self.model
            .move_subtree(&id, &new_id, TimeExpect::window(before, after));
        new_id
    }

    async fn delete(&mut self, space: &Space, id: FsHandle) {
        let ok = files_tree::delete_inode_recursive_tree(space, id.clone())
            .await
            .expect("delete_inode_recursive_tree");
        assert!(
            ok,
            "delete_inode_recursive_tree({id:?}) should remove at least one node"
        );
        self.model.delete_recursive(&id);
    }

    fn rebase(&self, id: FsHandle, old_root: &FsHandle, new_root: &FsHandle) -> FsHandle {
        assert!(
            id.0.len() >= old_root.0.len() && id.0[..old_root.0.len()] == old_root.0[..],
            "rebase: {id:?} is not under {old_root:?}"
        );
        let mut rebased = new_root.0.clone();
        rebased.extend_from_slice(&id.0[old_root.0.len()..]);
        FsHandle(rebased)
    }

    async fn list_author_names(&self, space: &Space, parent: FsHandle) -> Vec<(FsHandle, String)> {
        files_tree::list_children_tree(space, parent)
            .await
            .expect("list_children_tree")
            .into_iter()
            .map(|entry| (entry.id, entry.author_name))
            .collect()
    }

    async fn check_cold_read(&self, world: &World, reader: &str) {
        assert_tree_cold_read(world, reader, &self.model)
            .await
            .unwrap_or_else(|e| panic!("[{:?}] cold read for `{reader}` failed: {e}", self.kind()));
    }

    async fn check_warm(&self, space: &Space) {
        assert_tree_matches_model(space, &self.model).await;
    }

    async fn removed_user_create_folder(&self, space: &Space, uid: i64) -> Result<(), String> {
        files_tree::create_folder_tree(space, FsHandle::root(), uid, "blocked")
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    async fn removed_user_upload_file(&self, space: &Space, uid: i64) -> Result<(), String> {
        files_tree::upload_files_tree(
            space,
            FsHandle::root(),
            uid,
            vec![pending("blocked.txt", "text/plain", b"x")],
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
    }

    async fn removed_user_rename(&self, space: &Space, target: FsHandle) -> Result<(), String> {
        files_tree::rename_inode_tree(space, target, "renamed-by-removed")
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    async fn removed_user_move(
        &self,
        space: &Space,
        target: FsHandle,
        dest: FsHandle,
    ) -> Result<(), String> {
        files_tree::move_inode_tree(space, target, dest)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    async fn removed_user_delete(&self, space: &Space, target: FsHandle) -> Result<(), String> {
        files_tree::delete_inode_recursive_tree(space, target)
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
}

// ─── Cold-read variants (layer 3) ───────────────────────────────────────────

/// The Stage T1 gate (`create_file_roundtrip`), but read back through a second
/// actor's cold cache: A uploads via the verb, B syncs, then the whole read
/// surface (fields, bytes, ordering, reachability) must agree with the model at
/// the committed layer.
#[tokio::test]
async fn cold_read_create_file_roundtrip() {
    cold_read_create_file_roundtrip_body(TableBackend::wrapper()).await;
}

#[tokio::test]
async fn cold_read_create_file_roundtrip_native_writes() {
    cold_read_create_file_roundtrip_body(TableBackend::native()).await;
}

#[tokio::test]
async fn cold_read_create_file_roundtrip_tree() {
    cold_read_create_file_roundtrip_body(TreeBackend::new()).await;
}

async fn cold_read_create_file_roundtrip_body<B: FsScenarioBackend>(mut backend: B) {
    let world = two_actor_world("alice", "bob", "general").await.unwrap();
    let (alice, alice_uid) = actor_handle(&world, "alice");
    let root = backend.root();

    backend
        .upload_file(
            &alice,
            "alice",
            alice_uid,
            root,
            "notes.txt",
            b"hello world",
        )
        .await;

    backend.check_cold_read(&world, "bob").await;
}

/// A full create / rename / move / delete-file / delete-subtree lifecycle,
/// asserting the cold reader's view after every mutation. Mirrors the
/// single-space `deep_tree_consistency` test but at the KV layer through actor
/// B. Covers create file+folder, rename, move-directory-with-descendants,
/// delete-file, and delete-directory-subtree from the Stage T4 list.
#[tokio::test]
async fn cold_read_full_lifecycle() {
    cold_read_full_lifecycle_body(TableBackend::wrapper()).await;
}

#[tokio::test]
async fn cold_read_full_lifecycle_native_writes() {
    cold_read_full_lifecycle_body(TableBackend::native()).await;
}

#[tokio::test]
async fn cold_read_full_lifecycle_tree() {
    cold_read_full_lifecycle_body(TreeBackend::new()).await;
}

async fn cold_read_full_lifecycle_body<B: FsScenarioBackend>(mut backend: B) {
    let world = two_actor_world("alice", "bob", "general").await.unwrap();
    let (alice, uid) = actor_handle(&world, "alice");
    let root = backend.root();

    let docs = backend
        .create_folder(&alice, "alice", uid, root.clone(), "docs")
        .await;
    backend.check_cold_read(&world, "bob").await;

    let archive = backend
        .create_folder(&alice, "alice", uid, root.clone(), "archive")
        .await;
    let root_txt = backend
        .upload_file(&alice, "alice", uid, root.clone(), "root.txt", b"root")
        .await;
    let plan = backend
        .upload_file(&alice, "alice", uid, docs.clone(), "plan.md", b"plan")
        .await;
    let drafts = backend
        .create_folder(&alice, "alice", uid, docs.clone(), "drafts")
        .await;
    let draft = backend
        .upload_file(&alice, "alice", uid, drafts.clone(), "v1.md", b"v1")
        .await;
    backend.check_cold_read(&world, "bob").await;

    backend.rename(&alice, plan, "plan-final.md").await;
    backend.check_cold_read(&world, "bob").await;

    // Move the `drafts` subtree under `archive`. For the tree backend this
    // rebases `drafts` and its descendant `draft`; capture the new root handle
    // and rebase the descendant id the body still holds (a no-op for tables).
    let new_drafts = backend
        .move_to(&alice, drafts.clone(), archive.clone())
        .await;
    let draft = backend.rebase(draft, &drafts, &new_drafts);
    backend.check_cold_read(&world, "bob").await;

    backend.rename(&alice, draft, "v2.md").await;
    backend.check_cold_read(&world, "bob").await;

    // Delete a standalone file (delete-file coverage).
    backend.delete(&alice, root_txt).await;
    backend.check_cold_read(&world, "bob").await;

    // Deleting `archive` cascades to the `drafts` subtree it now holds
    // (delete-directory-subtree coverage).
    backend.delete(&alice, archive).await;
    backend.check_cold_read(&world, "bob").await;
}

// ─── Multi-user ──────────────────────────────────────────────────────────────

/// Two active users create inodes in the same directory; the `users_meta`
/// author join must resolve each entry's `author_name` to its own creator,
/// across users, at the committed layer.
#[tokio::test]
async fn list_dir_resolves_author_name() {
    list_dir_resolves_author_name_body(TableBackend::wrapper()).await;
}

#[tokio::test]
async fn list_dir_resolves_author_name_native_writes() {
    list_dir_resolves_author_name_body(TableBackend::native()).await;
}

#[tokio::test]
async fn list_dir_resolves_author_name_tree() {
    list_dir_resolves_author_name_body(TreeBackend::new()).await;
}

async fn list_dir_resolves_author_name_body<B: FsScenarioBackend>(mut backend: B) {
    let world = two_actor_world("alice", "bob", "general").await.unwrap();
    let (alice, alice_uid) = actor_handle(&world, "alice");
    let (bob, bob_uid) = actor_handle(&world, "bob");
    let root = backend.root();

    let alice_file = backend
        .upload_file(&alice, "alice", alice_uid, root.clone(), "alice.txt", b"a")
        .await;
    let alice_dir = backend
        .create_folder(&alice, "alice", alice_uid, root.clone(), "alice-dir")
        .await;
    // Bob catches up to Alice's writes before committing his own (avoids a
    // stale-base rejection — the harness syncs between writers for the same
    // reason).
    world.sync_all().await.unwrap();
    let bob_file = backend
        .upload_file(&bob, "bob", bob_uid, root.clone(), "bob.txt", b"b")
        .await;
    let bob_dir = backend
        .create_folder(&bob, "bob", bob_uid, root.clone(), "bob-dir")
        .await;

    // Each reader, after sync, must agree with the model — including the
    // per-entry `author_name` the model records as the creating actor's name.
    backend.check_cold_read(&world, "alice").await;
    backend.check_cold_read(&world, "bob").await;

    // Explicit author-name mapping check (states the cross-user intent directly),
    // through the backend's own list path and id type.
    let listing = backend.list_author_names(&alice, root).await;
    assert_eq!(listing.len(), 4, "four inodes at root: {listing:?}");
    for (id, author_name) in &listing {
        let expected = if *id == alice_file || *id == alice_dir {
            "alice"
        } else if *id == bob_file || *id == bob_dir {
            "bob"
        } else {
            panic!("unexpected inode id {id:?} in root listing");
        };
        assert_eq!(
            author_name, expected,
            "inode {id:?} author_name should be its creator"
        );
    }
}

/// `inodes` has no ownership `allow write` / `allow delete` rule, and
/// `delete_inode_recursive` is a raw `.delete()`, so a *non-author* active user
/// may rename, move, and delete another user's inode today. The tree backend's
/// native ops likewise gate only on an active caller, not authorship. A
/// reimplementation that adds an ownership check would change this — this test
/// catches it. Covers move-file and delete from the Stage T4 list.
#[tokio::test]
async fn non_author_can_mutate() {
    non_author_can_mutate_body(TableBackend::wrapper()).await;
}

#[tokio::test]
async fn non_author_can_mutate_native_writes() {
    non_author_can_mutate_body(TableBackend::native()).await;
}

#[tokio::test]
async fn non_author_can_mutate_tree() {
    non_author_can_mutate_body(TreeBackend::new()).await;
}

async fn non_author_can_mutate_body<B: FsScenarioBackend>(mut backend: B) {
    let world = two_actor_world("alice", "bob", "general").await.unwrap();
    let (alice, alice_uid) = actor_handle(&world, "alice");
    let (bob, _bob_uid) = actor_handle(&world, "bob");
    let root = backend.root();

    // Alice authors a folder and a file at root.
    let folder = backend
        .create_folder(&alice, "alice", alice_uid, root.clone(), "alice-folder")
        .await;
    let file = backend
        .upload_file(
            &alice,
            "alice",
            alice_uid,
            root.clone(),
            "alice-file.txt",
            b"owned by alice",
        )
        .await;
    // Bob catches up so the rows are in his view before he mutates them.
    world.sync_all().await.unwrap();

    // Bob (not the author) renames Alice's file. author_id/author_name are
    // untouched by rename, so the model still attributes it to Alice.
    backend
        .rename(&bob, file.clone(), "renamed-by-bob.txt")
        .await;
    backend.check_cold_read(&world, "alice").await;

    // Bob moves Alice's file into Alice's folder. The returned (possibly
    // rebased) handle is unused: the next step deletes the folder, cascading to
    // the file he just moved in.
    backend.move_to(&bob, file, folder.clone()).await;
    backend.check_cold_read(&world, "alice").await;

    // Bob deletes Alice's folder, cascading to the file he just moved in.
    backend.delete(&bob, folder).await;
    backend.check_cold_read(&world, "alice").await;

    // Bob's own warm view agrees too.
    world.sync_all().await.unwrap();
    backend.check_warm(&bob).await;
}

/// A *removed* user can no longer write: holding B's `Space` across the removal,
/// every `files` write verb (create folder, upload, rename, move, delete) must
/// error, and the author's tree must be unchanged.
///
/// This currently exposes the same SDK stale-removed-user key-manager/retention
/// self-deadlock as the chat consistency removed-user tests, so keep the harness
/// probes ignored until SDK stale recovery is fixed. Provisional-user rejection
/// remains covered at the changelog layer
/// (`native_ops_tests::*_rejects_provisional_user`).
#[tokio::test]
#[ignore = "exposes SDK stale-removed-user key-manager/retention self-deadlock; re-enable after SDK recovery fix"]
async fn removed_user_cannot_write() {
    removed_user_cannot_write_body(TableBackend::wrapper()).await;
}

#[tokio::test]
#[ignore = "exposes SDK stale-removed-user key-manager/retention self-deadlock; re-enable after SDK recovery fix"]
async fn removed_user_cannot_write_native_writes() {
    removed_user_cannot_write_body(TableBackend::native()).await;
}

#[tokio::test]
#[ignore = "exposes SDK stale-removed-user key-manager/retention self-deadlock; re-enable after SDK recovery fix"]
async fn removed_user_cannot_write_tree() {
    removed_user_cannot_write_body(TreeBackend::new()).await;
}

async fn removed_user_cannot_write_body<B: FsScenarioBackend>(mut backend: B) {
    let mut world = two_actor_world("alice", "bob", "general").await.unwrap();
    let (alice, alice_uid) = actor_handle(&world, "alice");
    // Capture Bob's handle before removal drops him from the world registry.
    let (bob, bob_uid) = actor_handle(&world, "bob");
    let root = backend.root();

    // Alice seeds a folder (and a move destination) so Bob has real targets.
    let target = backend
        .create_folder(&alice, "alice", alice_uid, root.clone(), "alice-folder")
        .await;
    let dest = backend
        .create_folder(&alice, "alice", alice_uid, root, "alice-dest")
        .await;
    world.sync_all().await.unwrap();

    // Alice evicts Bob (triggers a rekey); Bob's held handle is now stale.
    world.remove_user_actor("alice", "bob").await.unwrap();
    assert!(world.actor("bob").is_err(), "bob evicted from the world");

    // Every write verb must error for the removed user.
    let create = backend.removed_user_create_folder(&bob, bob_uid).await;
    assert!(
        create.is_err(),
        "removed user create_folder must error: {create:?}"
    );

    let upload = backend.removed_user_upload_file(&bob, bob_uid).await;
    assert!(
        upload.is_err(),
        "removed user upload_files must error: {upload:?}"
    );

    let rename = backend.removed_user_rename(&bob, target.clone()).await;
    assert!(
        rename.is_err(),
        "removed user rename must error: {rename:?}"
    );

    let moved = backend
        .removed_user_move(&bob, target.clone(), dest.clone())
        .await;
    assert!(moved.is_err(), "removed user move must error: {moved:?}");

    let deleted = backend.removed_user_delete(&bob, target.clone()).await;
    assert!(
        deleted.is_err(),
        "removed user delete must error: {deleted:?}"
    );

    // None of the failed writes mutated the tree the author still sees.
    world.sync_all().await.unwrap();
    backend.check_warm(&alice).await;
}

// ─── Harness MoveLastInode / DeleteLastInode smoke (layer 4) ─────────────────

/// Drives the `MoveLastInode` action end-to-end and reads the result back from
/// a second actor. The destination folder's id is assigned by the backend, so
/// the scenario runs in two phases: create, learn the id, then move.
#[tokio::test]
async fn move_last_inode_propagates_across_actors() {
    let setup = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::CreateFolder {
                parent_id: 0,
                name: "dest".into(),
            },
        ),
        (
            "alice".into(),
            Action::UploadFile {
                parent_id: 0,
                name: "movable.txt".into(),
                content: "payload".into(),
            },
        ),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&setup).await.expect("setup scenario");

    // Learn the destination folder's backend-assigned id.
    let alice = runner.world.actor("alice").unwrap();
    let dest_id = files::list_children(&alice.space, 0)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "dest")
        .and_then(|i| i.id)
        .expect("dest folder exists");

    // The last created inode is `movable.txt`; move it under `dest`.
    let move_step = Scenario::new(vec![(
        "alice".into(),
        Action::MoveLastInode {
            new_parent_id: dest_id,
        },
    )]);
    runner.execute(&move_step).await.expect("move scenario");

    // Bob reads back: `movable.txt` left root and now lives under `dest`.
    let bob = runner.world.actor("bob").unwrap();
    bob.space.sync().await.unwrap();
    let root = files::list_children(&bob.space, 0).await.unwrap();
    assert!(
        root.iter().any(|i| i.name == "dest"),
        "dest should remain at root: {root:?}"
    );
    assert!(
        !root.iter().any(|i| i.name == "movable.txt"),
        "movable.txt should have left root: {root:?}"
    );
    let under_dest = files::list_children(&bob.space, dest_id).await.unwrap();
    assert!(
        under_dest.iter().any(|i| i.name == "movable.txt"),
        "movable.txt should be under dest: {under_dest:?}"
    );
}

/// Drives the `DeleteLastInode` action end-to-end and reads the result back
/// from a second actor: the last-created inode is gone, a sibling survives.
#[tokio::test]
async fn delete_last_inode_propagates_across_actors() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::CreateFolder {
                parent_id: 0,
                name: "keep".into(),
            },
        ),
        (
            "alice".into(),
            Action::CreateFolder {
                parent_id: 0,
                name: "doomed".into(),
            },
        ),
        // `doomed` is the last created inode — DeleteLastInode removes it.
        ("alice".into(), Action::DeleteLastInode),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    let bob = runner.world.actor("bob").unwrap();
    bob.space.sync().await.unwrap();
    let root = files::list_children(&bob.space, 0).await.unwrap();
    let names: Vec<&str> = root.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"keep"), "keep should survive: {names:?}");
    assert!(
        !names.contains(&"doomed"),
        "doomed should be deleted: {names:?}"
    );
}
