//! Reference filesystem model + invariant checker for the `files` verb tests.
//!
//! This is the centerpiece of the self-consistent filesystem test suite (see
//! `docs/native_ops_plans/PLAN_FS_TEST.md`). It maintains a tiny in-memory
//! [`FsModel`] — the test's own record of what it asked the `files` write verbs
//! to do — and [`assert_matches_model`] checks the **read surface** of the
//! `files` module ([`crate::files::list_children`],
//! [`crate::files::download_file`], [`crate::files::download_file_by_hash`])
//! against that model.
//!
//! The checker references only verb *semantics*, never implementation
//! internals or hard-coded bytes, so it stays valid when the read and/or write
//! paths are reimplemented (data-driven → native ops, `SELECT` → read ops),
//! even simultaneously: a green check means "observable behavior preserved".
//!
//! It is reader-agnostic — `assert_matches_model` takes any `&Space`, so the
//! same model can be validated against the writer's own (warm-cache) space and
//! against a second actor's (cold-cache, post-sync) space at the committed / KV
//! layer.
//!
//! Compiled only for the crate's own tests (`cfg(test)`) and for the harness
//! crate via the `test-support` feature; it is absent from the production Tauri
//! binary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use encrypted_spaces_sdk::Space;

use crate::files::{self, Inode, InodeWithAuthor};
use crate::files_tree::{self, FsHandle, TreeInode, TreeInodeWithAuthor};

/// How a node's `ctime` / `mtime` should be checked against the read surface.
///
/// - [`TimeExpect::Exact`] — for **SDK-seeded** fixtures established with
///   controlled, strictly-increasing timestamps (`space.add_inode` with
///   explicit `ctime`/`mtime`): the read verbs must return them by value.
/// - [`TimeExpect::Window`] — for **wrapper-driven** writes (`create_folder`,
///   `upload_files`, `rename_inode`, `move_inode`), which stamp
///   `Utc::now().timestamp()` internally: the value must fall within the
///   before/after wall-clock window captured around the call. Never a bare
///   inequality — the 1-second stamp granularity makes "mtime changed" flaky.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeExpect {
    /// The timestamp must equal this value exactly.
    Exact(i64),
    /// The timestamp must satisfy `lo <= t <= hi`.
    Window { lo: i64, hi: i64 },
}

impl TimeExpect {
    /// Convenience constructor for an inclusive before/after window.
    pub fn window(lo: i64, hi: i64) -> Self {
        TimeExpect::Window { lo, hi }
    }

    fn check(&self, field: &str, ctx: &str, actual: i64) {
        match *self {
            TimeExpect::Exact(v) => {
                assert_eq!(actual, v, "{ctx}: {field} expected exact {v}, got {actual}");
            }
            TimeExpect::Window { lo, hi } => assert!(
                actual >= lo && actual <= hi,
                "{ctx}: {field} {actual} not within window [{lo}, {hi}]"
            ),
        }
    }
}

/// One inode the test believes exists, with the fields the read surface should
/// report. `id` is the map key in [`FsModel`]; the root (`id == 0`) is implicit.
#[derive(Debug, Clone)]
pub struct Node {
    /// `parent_id` (0 == root).
    pub parent: i64,
    pub name: String,
    /// `author_id`.
    pub author: i64,
    /// Expected `author_name` from the `users_meta` join.
    pub author_name: String,
    /// `type` column: [`crate::files::INODE_FILE`] or
    /// [`crate::files::INODE_FOLDER`].
    pub inode_type: i64,
    pub size: i64,
    /// `mime_type` column.
    pub mime: String,
    /// Hex content hash of `file_hash` (folders use 64 zeros).
    pub file_hash: String,
    pub ctime: TimeExpect,
    pub mtime: TimeExpect,
    /// Decrypted bytes for file nodes whose content the test knows; `None` for
    /// folders or files whose bytes aren't tracked. When `Some`, the bytes
    /// round-trip through `download_file` / `download_file_by_hash` is checked.
    pub bytes: Option<Vec<u8>>,
}

/// The fixed `file_hash` the demo stamps on folder inodes (no content): 64 hex
/// zeros. Pass this as [`CreateArgs::file_hash`] for folder creates so the
/// returned hash is asserted exactly (folders carry no bytes, so there is no
/// round-trip to catch a wrong hash otherwise).
pub const FOLDER_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const _: () = assert!(
    FOLDER_HASH_HEX.len() == 64,
    "folder hash must be 64 hex chars"
);

/// What a wrapper create (`create_folder` / `upload_files`) was *asked* to do.
/// The model node is built from these **call arguments**, and the returned
/// [`Inode`] is separately asserted to echo them (see
/// [`FsModel::record_created`]) — so a write+return that consistently produces
/// the wrong value cannot pass. `id` and `file_hash` are backend-assigned, not
/// arguments: `file_hash` is content-verified by the bytes round-trip and `id`
/// by listing membership.
pub struct CreateArgs<'a> {
    pub parent: i64,
    pub name: &'a str,
    pub author: i64,
    pub author_name: &'a str,
    pub inode_type: i64,
    pub size: i64,
    pub mime: &'a str,
    /// Expected content hash (hex). `Some` for fixed-hash creates like folders
    /// ([`FOLDER_HASH_HEX`]) — asserted exactly. `None` for content-addressed
    /// files, whose hash is verified by the bytes round-trip (requires
    /// `bytes: Some`).
    pub file_hash: Option<&'a str>,
    pub bytes: Option<Vec<u8>>,
    pub ctime: TimeExpect,
    pub mtime: TimeExpect,
}

/// The test's record of the filesystem state it asked the write verbs to
/// produce. Not the implementation's state — the read surface is asserted
/// against *this*.
#[derive(Debug, Default)]
pub struct FsModel {
    /// Live inodes, keyed by id.
    nodes: BTreeMap<i64, Node>,
    /// Ids that have been deleted (must appear in no listing and error on
    /// `download_file`).
    deleted: BTreeSet<i64>,
}

impl FsModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a node produced by a **wrapper** write verb (`create_folder`,
    /// `upload_files`) from the test's [`CreateArgs`], and assert the returned
    /// [`Inode`] echoes those arguments. The model node uses the *arguments* for
    /// every value field; only `id` and `file_hash` come from the returned row
    /// (both verified elsewhere — see [`CreateArgs`]). This keeps the model
    /// independent of the write implementation, as the plan requires.
    pub fn record_created(&mut self, returned: &Inode, args: CreateArgs<'_>) {
        let id = returned.id.expect("created inode must have an id");
        // Independence check: the returned row must match what we asked for, so
        // neither the model (built from args below) nor the read assertions can
        // be fooled by a consistently-wrong write+return.
        assert_eq!(
            returned.parent_id, args.parent,
            "create: returned parent_id != requested"
        );
        assert_eq!(
            returned.name, args.name,
            "create: returned name != requested"
        );
        assert_eq!(
            returned.author_id, args.author,
            "create: returned author_id != requested"
        );
        assert_eq!(
            returned.inode_type, args.inode_type,
            "create: returned type != requested"
        );
        assert_eq!(
            returned.size, args.size,
            "create: returned size != requested"
        );
        assert_eq!(
            returned.mime_type, args.mime,
            "create: returned mime_type != requested"
        );
        // `id` and `file_hash` come from the returned row. For content-addressed
        // files (`args.file_hash == None`) the hash is verified by the bytes
        // round-trip in `assert_matches_model` (which requires `bytes: Some`).
        // For fixed-hash creates like folders (`bytes: None`, no round-trip) the
        // caller supplies the expected hash and we assert it here — otherwise a
        // rewritten create could store and return a wrong folder hash unnoticed.
        let returned_hash = returned
            .file_hash
            .hash()
            .expect("recorded inode file_hash must be a hash, not pending data")
            .to_string();
        let file_hash = match args.file_hash {
            Some(expected) => {
                assert_eq!(
                    returned_hash, expected,
                    "create: returned file_hash != requested"
                );
                expected.to_string()
            }
            None => {
                assert!(
                    args.bytes.is_some(),
                    "create: a content-addressed file_hash (None) needs bytes so the round-trip verifies it"
                );
                returned_hash
            }
        };
        self.nodes.insert(
            id,
            Node {
                parent: args.parent,
                name: args.name.to_string(),
                author: args.author,
                author_name: args.author_name.to_string(),
                inode_type: args.inode_type,
                size: args.size,
                mime: args.mime.to_string(),
                file_hash,
                ctime: args.ctime,
                mtime: args.mtime,
                bytes: args.bytes,
            },
        );
    }

    /// Record a node established by **directly seeding** the SDK
    /// (`space.add_inode(&entry)`) with controlled `ctime`/`mtime`. The model
    /// records those exact values so the read verbs are asserted by value.
    pub fn record_seeded(&mut self, inode: &Inode, author_name: &str, bytes: Option<Vec<u8>>) {
        self.insert_inode(
            inode,
            author_name,
            bytes,
            TimeExpect::Exact(inode.ctime),
            TimeExpect::Exact(inode.mtime),
        );
    }

    fn insert_inode(
        &mut self,
        inode: &Inode,
        author_name: &str,
        bytes: Option<Vec<u8>>,
        ctime: TimeExpect,
        mtime: TimeExpect,
    ) {
        let id = inode.id.expect("recorded inode must have an id");
        let file_hash = inode
            .file_hash
            .hash()
            .expect("recorded inode file_hash must be a hash, not pending data")
            .to_string();
        self.nodes.insert(
            id,
            Node {
                parent: inode.parent_id,
                name: inode.name.clone(),
                author: inode.author_id,
                author_name: author_name.to_string(),
                inode_type: inode.inode_type,
                size: inode.size,
                mime: inode.mime_type.clone(),
                file_hash,
                ctime,
                mtime,
                bytes,
            },
        );
    }

    /// Apply rename semantics: set `name` and `mtime`; leave everything else
    /// (incl. `ctime`, `parent`, `author`, `type`, `size`, `mime`,
    /// `file_hash`) untouched. No-op if the id is unknown (mirrors the
    /// missing-target write being a no-op).
    pub fn rename(&mut self, id: i64, new_name: &str, mtime: TimeExpect) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.name = new_name.to_string();
            n.mtime = mtime;
        }
    }

    /// Apply move semantics: set `parent` and `mtime`; leave everything else
    /// untouched. No-op if the id is unknown.
    pub fn reparent(&mut self, id: i64, new_parent: i64, mtime: TimeExpect) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.parent = new_parent;
            n.mtime = mtime;
        }
    }

    /// Apply recursive-delete semantics: remove `id` and all of its
    /// descendants, recording each removed id as deleted. Unknown ids are a
    /// no-op (they aren't recorded as deleted).
    pub fn delete_recursive(&mut self, id: i64) {
        // Breadth-first collect of the subtree rooted at `id` (including `id`).
        let mut subtree = vec![id];
        let mut i = 0;
        while i < subtree.len() {
            let cur = subtree[i];
            for (cid, n) in &self.nodes {
                if n.parent == cur {
                    subtree.push(*cid);
                }
            }
            i += 1;
        }
        for r in subtree {
            if self.nodes.remove(&r).is_some() {
                self.deleted.insert(r);
            }
        }
    }

    /// Live ids the model currently believes exist.
    fn live_ids(&self) -> BTreeSet<i64> {
        self.nodes.keys().copied().collect()
    }

    /// The parents whose listings must be checked: root, every live node's
    /// parent, every live node treated as a parent (so empty folders and
    /// folders' exact child sets are both verified), and every deleted id.
    ///
    /// Deleted ids are queried so a surviving descendant under a deleted folder
    /// is caught: such an orphan is unreachable from root, so the reachability
    /// walk alone misses it, but it appears as an unexpected child when its
    /// (deleted) parent is listed. A correctly cascaded delete leaves each
    /// deleted id with an empty listing.
    fn parents_to_query(&self) -> BTreeSet<i64> {
        let mut parents = BTreeSet::new();
        parents.insert(0);
        for (id, node) in &self.nodes {
            parents.insert(node.parent);
            parents.insert(*id);
        }
        parents.extend(self.deleted.iter().copied());
        parents
    }
}

/// One live node in the tree-backed filesystem model.
///
/// The map key in [`TreeFsModel`] is the current hierarchical handle. The
/// stable `inode_id` is the node's own 256-bit inode id — the last component of
/// its handle. A move rebases the parent prefix but preserves every node's own
/// id, so the checker can catch a move that changes a logical node's identity
/// while still rebasing the handle.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub parent: FsHandle,
    pub name: String,
    pub author: i64,
    pub author_name: String,
    pub inode_type: i64,
    pub size: i64,
    pub mime: String,
    pub file_hash: String,
    pub ctime: TimeExpect,
    pub mtime: TimeExpect,
    pub bytes: Option<Vec<u8>>,
    pub inode_id: files_tree::codec::InodeId,
}

/// What a tree create (`create_folder_tree` / `upload_files_tree`) was asked to
/// do. The returned [`TreeInode`] must echo these arguments; the model records
/// the arguments, not the read surface.
pub struct TreeCreateArgs<'a> {
    pub parent: FsHandle,
    pub name: &'a str,
    pub author: i64,
    pub author_name: &'a str,
    pub inode_type: i64,
    pub size: i64,
    pub mime: &'a str,
    pub file_hash: Option<&'a str>,
    pub bytes: Option<Vec<u8>>,
    pub ctime: TimeExpect,
    pub mtime: TimeExpect,
}

/// Reference model for the relative-inode tree backend.
///
/// Unlike [`FsModel`], this is keyed by hierarchical [`FsHandle`] values. A
/// move rebases the moved root and every descendant; the old handles are tracked
/// as stale so tests can assert they no longer address the moved nodes.
#[derive(Debug, Default)]
pub struct TreeFsModel {
    nodes: BTreeMap<FsHandle, TreeNode>,
    deleted_inode_ids: BTreeSet<files_tree::codec::InodeId>,
    stale_handles: BTreeSet<FsHandle>,
}

impl TreeFsModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a node produced by the tree create helpers. The stable identity
    /// (the node's own inode id, the returned handle's last component) is taken
    /// from the handle, the record's presence is confirmed by a raw read, and
    /// every user-visible field is still asserted from the call arguments.
    pub async fn record_created(
        &mut self,
        reader: &Space,
        returned: &TreeInode,
        args: TreeCreateArgs<'_>,
    ) {
        assert_eq!(
            returned.parent_id, args.parent,
            "tree create: returned parent_id != requested"
        );
        assert_eq!(
            returned.name, args.name,
            "tree create: returned name != requested"
        );
        assert_eq!(
            returned.author_id, args.author,
            "tree create: returned author_id != requested"
        );
        assert_eq!(
            returned.inode_type, args.inode_type,
            "tree create: returned type != requested"
        );
        assert_eq!(
            returned.size, args.size,
            "tree create: returned size != requested"
        );
        // The tree codec does not persist a MIME (deferred — DESIGN §0): the
        // read surface derives it from the name for files (folders carry none),
        // so the expected MIME comes from the name, not the requested `args.mime`.
        let expected_mime = expected_tree_mime(args.inode_type, args.name);
        assert_eq!(
            returned.mime_type, expected_mime,
            "tree create: returned mime_type != name-derived MIME"
        );

        let returned_hash = returned
            .file_hash
            .hash()
            .expect("tree created inode file_hash must be a hash, not pending data")
            .to_string();
        let file_hash = match args.file_hash {
            Some(expected) => {
                assert_eq!(
                    returned_hash, expected,
                    "tree create: returned file_hash != requested"
                );
                expected.to_string()
            }
            None => {
                assert!(
                    args.bytes.is_some(),
                    "tree create: content-addressed files need bytes for the round-trip check"
                );
                returned_hash
            }
        };
        // Confirm the create actually wrote a record at the returned handle; the
        // node's stable identity is its own inode id (the handle's last id).
        assert!(
            read_tree_inode(reader, &returned.id).await.is_some(),
            "tree create: no record for returned handle {:?}",
            returned.id
        );
        let inode_id = *returned
            .id
            .0
            .last()
            .expect("created tree handle is never the root");

        assert!(
            self.nodes
                .insert(
                    returned.id.clone(),
                    TreeNode {
                        parent: args.parent,
                        name: args.name.to_string(),
                        author: args.author,
                        author_name: args.author_name.to_string(),
                        inode_type: args.inode_type,
                        size: args.size,
                        mime: expected_mime,
                        file_hash,
                        ctime: args.ctime,
                        mtime: args.mtime,
                        bytes: args.bytes,
                        inode_id,
                    },
                )
                .is_none(),
            "tree create: duplicate handle {:?}",
            returned.id
        );
        self.stale_handles.remove(&returned.id);
    }

    /// Apply tree rename semantics: update `name` and `mtime`; keep the handle,
    /// parent, type, author, file reference, and stable `inode_id` unchanged.
    ///
    /// MIME is name-derived on the tree read surface (deferred — DESIGN §0), so a
    /// rename that changes the extension (e.g. `a.txt` → `a.png`) changes the
    /// expected MIME too; recompute it from the new name.
    pub fn rename(&mut self, id: &FsHandle, new_name: &str, mtime: TimeExpect) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.name = new_name.to_string();
            node.mime = expected_tree_mime(node.inode_type, new_name);
            node.mtime = mtime;
        }
    }

    /// Apply tree move semantics: rebase the moved root and every descendant
    /// from `old` to `new`, preserve every stable `inode_id`, and mark the old
    /// handles stale.
    pub fn move_subtree(&mut self, old: &FsHandle, new: &FsHandle, mtime: TimeExpect) {
        let moved: Vec<(FsHandle, TreeNode)> = self
            .nodes
            .iter()
            .filter(|(handle, _)| tree_handle_has_prefix(handle, old))
            .map(|(handle, node)| (handle.clone(), node.clone()))
            .collect();
        if moved.is_empty() {
            return;
        }

        for (old_handle, _) in &moved {
            self.nodes.remove(old_handle);
            self.stale_handles.insert(old_handle.clone());
        }

        for (old_handle, mut node) in moved {
            let new_handle = rebase_tree_handle(&old_handle, old, new)
                .expect("moved handle must have the old prefix");
            node.parent = if old_handle == *old {
                tree_parent_handle(new)
            } else {
                rebase_tree_handle(&node.parent, old, new)
                    .expect("descendant parent must have the old prefix")
            };
            if old_handle == *old {
                node.mtime = mtime;
            }
            assert!(
                self.nodes.insert(new_handle.clone(), node).is_none(),
                "tree move: rebased handle {:?} already exists",
                new_handle
            );
        }
    }

    /// Apply recursive delete semantics: remove the source and every descendant,
    /// remember their stable node ids, and mark their old handles stale.
    pub fn delete_recursive(&mut self, id: &FsHandle) {
        let deleted: Vec<FsHandle> = self
            .nodes
            .keys()
            .filter(|handle| tree_handle_has_prefix(handle, id))
            .cloned()
            .collect();
        for handle in deleted {
            if let Some(node) = self.nodes.remove(&handle) {
                self.deleted_inode_ids.insert(node.inode_id);
                self.stale_handles.insert(handle);
            }
        }
    }

    fn live_ids(&self) -> BTreeSet<FsHandle> {
        self.nodes.keys().cloned().collect()
    }

    fn parents_to_query(&self) -> BTreeSet<FsHandle> {
        let mut parents = BTreeSet::new();
        parents.insert(FsHandle::root());
        for (id, node) in &self.nodes {
            parents.insert(node.parent.clone());
            if node.inode_type == files::INODE_FOLDER {
                parents.insert(id.clone());
            }
        }
        parents
    }

    fn stale_handles(&self) -> impl Iterator<Item = &FsHandle> {
        self.stale_handles.iter()
    }
}

/// Assert the `files` read surface of `reader` agrees with `model` on every
/// invariant the verbs guarantee. Panics (test-assertion style) on any
/// mismatch.
///
/// Checks, per `PLAN_FS_TEST.md`:
/// 1. **Listing membership & fields** — each queried parent's `list_children`
///    returns exactly the model's children of that parent, matching on every
///    `InodeWithAuthor` field (incl. `author_name` and the per-node timestamp
///    expectation).
/// 2. **Bytes round-trip** — file nodes with known bytes round-trip through
///    `download_file` and `download_file_by_hash`.
/// 3. **Ordering** — every listing is folders-first then `ctime` desc (the
///    desc constraint enforced only among distinct `ctime`s).
/// 4. **Absence** — every deleted id appears in no listing and errors on
///    `download_file`.
/// 5. **Reachability / no orphans** — walking from root via `list_children`
///    reconstructs exactly the model's live set.
pub async fn assert_matches_model(reader: &Space, model: &FsModel) {
    let mut listed_ids: BTreeSet<i64> = BTreeSet::new();

    // (1) + (3): membership, fields, and ordering for every relevant parent.
    for parent in model.parents_to_query() {
        let listing = list_children(reader, parent).await;
        assert_ordering(&listing, parent);

        let expected: BTreeMap<i64, &Node> = model
            .nodes
            .iter()
            .filter(|(_, n)| n.parent == parent)
            .map(|(id, n)| (*id, n))
            .collect();

        // Build the id set while rejecting duplicates explicitly — a plain
        // `collect()` into a set would silently merge two entries sharing an
        // id and hide a duplicate-listing bug.
        let mut got_ids: BTreeSet<i64> = BTreeSet::new();
        for entry in &listing {
            let id = entry.id.expect("listed inode must have an id");
            assert!(
                got_ids.insert(id),
                "list_children({parent}): duplicate inode id {id} in listing"
            );
        }
        let expected_ids: BTreeSet<i64> = expected.keys().copied().collect();
        assert_eq!(
            got_ids, expected_ids,
            "list_children({parent}): child id set mismatch (got {got_ids:?}, expected {expected_ids:?})"
        );

        for entry in &listing {
            let id = entry.id.unwrap();
            let node = expected
                .get(&id)
                .unwrap_or_else(|| panic!("list_children({parent}) returned unexpected id {id}"));
            assert_fields(entry, node, parent);
            listed_ids.insert(id);
        }
    }

    // (2): bytes round-trip for file nodes whose content the model knows.
    for (id, node) in &model.nodes {
        if let Some(expected_bytes) = &node.bytes {
            let by_id = files::download_file(reader, *id)
                .await
                .unwrap_or_else(|e| panic!("download_file({id}) failed: {e}"));
            assert_eq!(
                &by_id, expected_bytes,
                "download_file({id}) returned unexpected bytes"
            );
            let by_hash = files::download_file_by_hash(reader, &node.file_hash)
                .await
                .unwrap_or_else(|e| {
                    panic!("download_file_by_hash({}) failed: {e}", node.file_hash)
                });
            assert_eq!(
                &by_hash, expected_bytes,
                "download_file_by_hash({}) returned unexpected bytes",
                node.file_hash
            );
        }
    }

    // (5): reachability — reconstruct the live set by walking from the root.
    let reachable = walk_from_root(reader).await;
    assert_eq!(
        reachable,
        model.live_ids(),
        "reachable-from-root set must equal the model's live set"
    );

    // (4): absence — deleted ids are gone from listings and error on read.
    for deleted in &model.deleted {
        assert!(
            !listed_ids.contains(deleted),
            "deleted id {deleted} still appears in a listing"
        );
        assert!(
            !reachable.contains(deleted),
            "deleted id {deleted} is still reachable from root"
        );
        let res = files::download_file(reader, *deleted).await;
        match res {
            Ok(_) => panic!("download_file({deleted}) on a deleted inode should error"),
            Err(e) => {
                // Require the *inode-lookup* error specifically. A surviving
                // inode row whose blob is missing fails later with a generic
                // "file not found", which a loose `contains("not found")` would
                // wrongly accept — masking a row that should have been deleted.
                let msg = format!("{e}");
                let expected = format!("inode {deleted} not found");
                assert!(
                    msg.contains(&expected),
                    "download_file({deleted}) on a deleted inode should fail the inode lookup with {expected:?}, got: {msg}"
                );
            }
        }
    }
}

/// `list_children` wrapper that unwraps with context.
async fn list_children(reader: &Space, parent: i64) -> Vec<InodeWithAuthor> {
    files::list_children(reader, parent)
        .await
        .unwrap_or_else(|e| panic!("list_children({parent}) failed: {e}"))
}

/// Assert every non-timestamp field matches by value, and `ctime`/`mtime`
/// match the node's [`TimeExpect`].
fn assert_fields(entry: &InodeWithAuthor, node: &Node, parent: i64) {
    let id = entry.id.unwrap();
    let ctx = format!("inode {id} under parent {parent}");

    assert_eq!(entry.parent_id, node.parent, "{ctx}: parent_id");
    assert_eq!(
        entry.parent_id, parent,
        "{ctx}: listed under the wrong parent"
    );
    assert_eq!(entry.author_id, node.author, "{ctx}: author_id");
    assert_eq!(entry.name, node.name, "{ctx}: name");
    assert_eq!(entry.inode_type, node.inode_type, "{ctx}: type");
    assert_eq!(entry.size, node.size, "{ctx}: size");
    assert_eq!(entry.mime_type, node.mime, "{ctx}: mime_type");
    let got_hash = entry
        .file_hash
        .hash()
        .expect("listed file_hash must be a hash");
    assert_eq!(got_hash, node.file_hash, "{ctx}: file_hash");
    assert_eq!(entry.author_name, node.author_name, "{ctx}: author_name");
    node.ctime.check("ctime", &ctx, entry.ctime);
    node.mtime.check("mtime", &ctx, entry.mtime);
}

/// Assert a listing is folders-first then `ctime` desc. The desc constraint is
/// enforced only among distinct `ctime`s — equal `ctime`s may appear in any
/// order (the demo wrappers stamp at 1-second granularity, so collisions are
/// expected and their relative order is undefined / stable-sort dependent).
fn assert_ordering(listing: &[InodeWithAuthor], parent: i64) {
    for pair in listing.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        // Folders (type 2) sort before files (type 1): type is non-increasing.
        assert!(
            a.inode_type >= b.inode_type,
            "list_children({parent}): folders must precede files (saw type {} before type {})",
            a.inode_type,
            b.inode_type
        );
        // Within a type group, ctime must be non-increasing (desc); equality is
        // allowed, so this only constrains distinct ctimes.
        if a.inode_type == b.inode_type {
            assert!(
                a.ctime >= b.ctime,
                "list_children({parent}): within a type group ctime must be descending (saw {} before {})",
                a.ctime,
                b.ctime
            );
        }
    }
}

/// Walk the tree from the root via `list_children`, returning every reachable
/// id. A visited-parent guard makes the walk robust to any (illegal) cycle.
async fn walk_from_root(reader: &Space) -> BTreeSet<i64> {
    let mut reachable = BTreeSet::new();
    let mut queue: VecDeque<i64> = VecDeque::new();
    let mut visited_parents: BTreeSet<i64> = BTreeSet::new();
    queue.push_back(0);
    while let Some(parent) = queue.pop_front() {
        if !visited_parents.insert(parent) {
            continue;
        }
        for entry in list_children(reader, parent).await {
            let id = entry.id.expect("listed inode must have an id");
            if reachable.insert(id) {
                queue.push_back(id);
            }
        }
    }
    reachable
}

/// Assert the tree read surface agrees with the independent handle-keyed model.
///
/// This uses the same Tauri-shaped helper path as the demo: list by
/// [`FsHandle`], download by [`FsHandle`], and download by content hash. The
/// only raw tree reads confirm a listed handle resolves to a real [`Inode`]
/// record and gather every live record's own inode id — the stable logical
/// identity the model tracks across moves/deletes (it lives in the record key,
/// not in `TreeInodeWithAuthor`).
pub async fn assert_tree_matches_model(reader: &Space, model: &TreeFsModel) {
    let mut listed_ids: BTreeSet<FsHandle> = BTreeSet::new();

    for parent in model.parents_to_query() {
        let listing = list_tree_children(reader, &parent).await;
        assert_tree_ordering(&listing, &parent);

        let expected: BTreeMap<FsHandle, &TreeNode> = model
            .nodes
            .iter()
            .filter(|(_, node)| node.parent == parent)
            .map(|(id, node)| (id.clone(), node))
            .collect();

        let mut got_ids: BTreeSet<FsHandle> = BTreeSet::new();
        for entry in &listing {
            assert!(
                got_ids.insert(entry.id.clone()),
                "list_children_tree({:?}): duplicate handle {:?} in listing",
                parent,
                entry.id
            );
        }
        let expected_ids: BTreeSet<FsHandle> = expected.keys().cloned().collect();
        assert_eq!(
            got_ids, expected_ids,
            "list_children_tree({:?}): child handle set mismatch (got {:?}, expected {:?})",
            parent, got_ids, expected_ids
        );

        for entry in &listing {
            let node = expected.get(&entry.id).unwrap_or_else(|| {
                panic!(
                    "list_children_tree({:?}) returned unexpected handle {:?}",
                    parent, entry.id
                )
            });
            assert_tree_fields(reader, entry, node, &parent).await;
            listed_ids.insert(entry.id.clone());
        }
    }

    for (id, node) in &model.nodes {
        if let Some(expected_bytes) = &node.bytes {
            let by_handle = files_tree::download_file_tree(reader, id.clone())
                .await
                .unwrap_or_else(|e| panic!("download_file_tree({:?}) failed: {e}", id));
            assert_eq!(
                &by_handle, expected_bytes,
                "download_file_tree({:?}) returned unexpected bytes",
                id
            );
            let by_hash = files::download_file_by_hash(reader, &node.file_hash)
                .await
                .unwrap_or_else(|e| {
                    panic!("download_file_by_hash({}) failed: {e}", node.file_hash)
                });
            assert_eq!(
                &by_hash, expected_bytes,
                "download_file_by_hash({}) returned unexpected bytes",
                node.file_hash
            );
        }
    }

    let reachable = walk_tree_from_root(reader).await;
    assert_eq!(
        reachable,
        model.live_ids(),
        "tree reachable-from-root set must equal the model's live handle set"
    );

    let live_inode_ids = live_tree_inode_ids(reader).await;
    for deleted_inode_id in &model.deleted_inode_ids {
        assert!(
            !live_inode_ids.contains_key(deleted_inode_id),
            "deleted tree inode_id {} is still present at {:?}",
            hex::encode(deleted_inode_id),
            live_inode_ids.get(deleted_inode_id)
        );
    }

    for stale in model.stale_handles() {
        assert!(
            !listed_ids.contains(stale),
            "stale tree handle {:?} still appears in a listing",
            stale
        );
        assert!(
            !reachable.contains(stale),
            "stale tree handle {:?} is still reachable from root",
            stale
        );
        assert!(
            read_tree_inode(reader, stale).await.is_none(),
            "stale tree handle {:?} still has a node record",
            stale
        );
        assert!(
            files_tree::download_file_tree(reader, stale.clone())
                .await
                .is_err(),
            "download_file_tree({:?}) on a stale handle should error",
            stale
        );
    }
}

/// Assert stale handles cannot mutate the tree backend. This intentionally uses
/// the write helpers at the end of a scenario: each stale write must be a no-op
/// (`false` / `new_id: None`) rather than rebinding the old handle to the moved
/// or deleted node.
pub async fn assert_tree_stale_handle_writes_rejected(space: &Space, model: &TreeFsModel) {
    for stale in model.stale_handles() {
        assert!(
            read_tree_inode(space, stale).await.is_none(),
            "stale tree handle {:?} must be absent before write rejection checks",
            stale
        );
        assert!(
            !files_tree::rename_inode_tree(space, stale.clone(), "__stale_handle__")
                .await
                .unwrap_or_else(|e| panic!("rename stale tree handle {:?} failed: {e}", stale)),
            "rename_inode_tree({:?}) should be a no-op for a stale handle",
            stale
        );
        let moved = files_tree::move_inode_tree(space, stale.clone(), FsHandle::root())
            .await
            .unwrap_or_else(|e| panic!("move stale tree handle {:?} failed: {e}", stale));
        assert!(
            !moved.moved && moved.new_id.is_none(),
            "move_inode_tree({:?}) should be a no-op for a stale handle, got {:?}",
            stale,
            moved
        );
        assert!(
            !files_tree::delete_inode_recursive_tree(space, stale.clone())
                .await
                .unwrap_or_else(|e| panic!("delete stale tree handle {:?} failed: {e}", stale)),
            "delete_inode_recursive_tree({:?}) should be a no-op for a stale handle",
            stale
        );
    }
}

async fn list_tree_children(reader: &Space, parent: &FsHandle) -> Vec<TreeInodeWithAuthor> {
    files_tree::list_children_tree(reader, parent.clone())
        .await
        .unwrap_or_else(|e| panic!("list_children_tree({parent:?}) failed: {e}"))
}

async fn assert_tree_fields(
    reader: &Space,
    entry: &TreeInodeWithAuthor,
    node: &TreeNode,
    parent: &FsHandle,
) {
    let ctx = format!("tree inode {:?} under parent {:?}", entry.id, parent);

    assert_eq!(entry.parent_id, node.parent, "{ctx}: parent_id");
    assert_eq!(
        entry.parent_id, *parent,
        "{ctx}: listed under the wrong parent"
    );
    assert_eq!(entry.author_id, node.author, "{ctx}: author_id");
    assert_eq!(entry.name, node.name, "{ctx}: name");
    assert_eq!(entry.inode_type, node.inode_type, "{ctx}: type");
    assert_eq!(entry.size, node.size, "{ctx}: size");
    assert_eq!(entry.mime_type, node.mime, "{ctx}: mime_type");
    let got_hash = entry
        .file_hash
        .hash()
        .expect("listed tree file_hash must be a hash");
    assert_eq!(got_hash, node.file_hash, "{ctx}: file_hash");
    assert_eq!(entry.author_name, node.author_name, "{ctx}: author_name");
    node.ctime.check("ctime", &ctx, entry.ctime);
    node.mtime.check("mtime", &ctx, entry.mtime);

    // Confirm the listed handle resolves to a real record, and that its stable
    // identity (its own inode id, the handle's last component) is unchanged.
    assert!(
        read_tree_inode(reader, &entry.id).await.is_some(),
        "{ctx}: listed handle has no Inode record"
    );
    let inode_id = *entry
        .id
        .0
        .last()
        .expect("listed tree handle is never the root");
    assert_eq!(inode_id, node.inode_id, "{ctx}: stable inode_id changed");
}

fn assert_tree_ordering(listing: &[TreeInodeWithAuthor], parent: &FsHandle) {
    for pair in listing.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        assert!(
            a.inode_type >= b.inode_type,
            "list_children_tree({parent:?}): folders must precede files (saw type {} before type {})",
            a.inode_type,
            b.inode_type
        );
        if a.inode_type == b.inode_type {
            assert!(
                a.ctime >= b.ctime,
                "list_children_tree({parent:?}): within a type group ctime must be descending (saw {} before {})",
                a.ctime,
                b.ctime
            );
        }
    }
}

async fn walk_tree_from_root(reader: &Space) -> BTreeSet<FsHandle> {
    let mut reachable = BTreeSet::new();
    let mut queue: VecDeque<FsHandle> = VecDeque::new();
    let mut visited_dirs: BTreeSet<FsHandle> = BTreeSet::new();
    queue.push_back(FsHandle::root());
    while let Some(parent) = queue.pop_front() {
        if !visited_dirs.insert(parent.clone()) {
            continue;
        }
        for entry in list_tree_children(reader, &parent).await {
            if reachable.insert(entry.id.clone()) && entry.inode_type == files::INODE_FOLDER {
                queue.push_back(entry.id);
            }
        }
    }
    reachable
}

/// Expected read-surface MIME for a tree node. The tree codec does not persist
/// a MIME (deferred — DESIGN §0), so the read surface derives it from the name
/// for files; folders carry none.
fn expected_tree_mime(inode_type: i64, name: &str) -> String {
    if inode_type == files::INODE_FOLDER {
        String::new()
    } else {
        files::mime_from_extension(name)
    }
}

async fn read_tree_inode(reader: &Space, handle: &FsHandle) -> Option<files_tree::codec::Inode> {
    let key = files_tree::codec::encode_record_key(&handle.0)
        .unwrap_or_else(|e| panic!("encode tree record key {:?}: {e}", handle));
    let bytes = reader
        .raw_read_key(key)
        .await
        .unwrap_or_else(|e| panic!("raw tree read {:?}: {e}", handle))?;
    Some(
        files_tree::codec::Inode::decode(&bytes)
            .unwrap_or_else(|e| panic!("decode tree record {:?}: {e}", handle)),
    )
}

/// Map every live tree record's own inode id (its handle's last component) to
/// its handle. Scans the whole `/_fs` namespace (`CONTAINER([])`).
async fn live_tree_inode_ids(reader: &Space) -> BTreeMap<files_tree::codec::InodeId, FsHandle> {
    let prefix = files_tree::codec::encode_container_prefix(&[])
        .expect("root tree container prefix should always encode");
    let records = reader
        .raw_read_prefix(prefix)
        .await
        .unwrap_or_else(|e| panic!("raw tree prefix read failed: {e}"));
    let mut out = BTreeMap::new();
    for (key, value) in records {
        // The whole-namespace scan also returns each directory's container
        // sentinel (`CONTAINER ‖ /cnt`, seeded by `tree_fs_create` so empty-dir
        // moves work), which is not a record key — skip anything that does not
        // decode as one.
        let Ok(path) = files_tree::codec::decode_record_key::<files_tree::codec::InodePath>(&key)
        else {
            continue;
        };
        files_tree::codec::Inode::decode(&value)
            .unwrap_or_else(|e| panic!("decode tree record at {:?}: {e}", path));
        let inode_id = *path.last().expect("tree record path is never the root");
        assert!(
            out.insert(inode_id, FsHandle(path)).is_none(),
            "duplicate live tree inode_id {}",
            hex::encode(inode_id)
        );
    }
    out
}

fn tree_handle_has_prefix(handle: &FsHandle, prefix: &FsHandle) -> bool {
    handle.0.len() >= prefix.0.len() && handle.0[..prefix.0.len()] == prefix.0
}

fn rebase_tree_handle(handle: &FsHandle, old: &FsHandle, new: &FsHandle) -> Option<FsHandle> {
    if !tree_handle_has_prefix(handle, old) {
        return None;
    }
    let mut rebased = new.0.clone();
    rebased.extend_from_slice(&handle.0[old.0.len()..]);
    Some(FsHandle(rebased))
}

fn tree_parent_handle(handle: &FsHandle) -> FsHandle {
    let mut parent = handle.0.clone();
    parent.pop();
    FsHandle(parent)
}

#[cfg(test)]
mod tests {
    //! White-box unit tests for the model's bookkeeping — the part of the
    //! checker that decides *what* the read surface gets asserted against.
    //! (The full read-surface assertions are exercised end-to-end against a
    //! live `Space` by the `files`-verb tests.)

    use super::*;
    use crate::files::{Inode, PendingFile};
    use encrypted_spaces_sdk::{ApplicationSchema, File, LocalTransport};

    fn folder(id: i64, parent: i64) -> Inode {
        Inode {
            id: Some(id),
            parent_id: parent,
            author_id: 1,
            name: format!("folder-{id}"),
            inode_type: crate::files::INODE_FOLDER,
            size: 0,
            ctime: 100,
            mtime: 100,
            mime_type: String::new(),
            file_hash: File::from_hash("0".repeat(64)),
        }
    }

    fn file(id: i64, parent: i64) -> Inode {
        Inode {
            id: Some(id),
            parent_id: parent,
            author_id: 1,
            name: format!("file-{id}"),
            inode_type: crate::files::INODE_FILE,
            size: 1,
            ctime: 100,
            mtime: 100,
            mime_type: "text/plain".to_string(),
            file_hash: File::from_hash("ab".repeat(32)),
        }
    }

    const TREE_TEST_USER_NAME: &str = "tree_model_user";
    const TEST_SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../app_schema.kdl");

    fn pending_tree(name: &str, mime: &str, data: &[u8]) -> PendingFile {
        PendingFile {
            data: data.to_vec(),
            filename: name.to_string(),
            mime_type: mime.to_string(),
        }
    }

    async fn create_tree_test_space() -> Space {
        std::env::set_var("RISC0_DEV_MODE", "1");
        let transport = LocalTransport::from_schema_file(TEST_SCHEMA_PATH)
            .await
            .unwrap();
        let commitment = transport.get_root_hash().await.unwrap();
        let space = Space::create(
            transport,
            ApplicationSchema::for_testing_from_bytes(crate::APP_SCHEMA_BYTES, commitment),
        )
        .await
        .unwrap();
        let uid = space.get_auth_context().uid.unwrap();
        crate::chat::set_user_name(&space, uid, TREE_TEST_USER_NAME)
            .await
            .unwrap();
        space
    }

    // Only the mrt-gated end-to-end test below uses this helper.
    #[cfg(feature = "mrt")]
    async fn create_tree_folder_recorded(
        space: &Space,
        model: &mut TreeFsModel,
        uid: i64,
        parent: FsHandle,
        name: &str,
    ) -> TreeInode {
        let before = chrono::Utc::now().timestamp();
        let inode = files_tree::create_folder_tree(space, parent.clone(), uid, name)
            .await
            .unwrap();
        let after = chrono::Utc::now().timestamp();
        model
            .record_created(
                space,
                &inode,
                TreeCreateArgs {
                    parent,
                    name,
                    author: uid,
                    author_name: TREE_TEST_USER_NAME,
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
        inode
    }

    async fn upload_tree_file_recorded(
        space: &Space,
        model: &mut TreeFsModel,
        uid: i64,
        parent: FsHandle,
        name: &str,
        data: &[u8],
    ) -> TreeInode {
        let before = chrono::Utc::now().timestamp();
        let mut created = files_tree::upload_files_tree(
            space,
            parent.clone(),
            uid,
            vec![pending_tree(name, "text/plain", data)],
        )
        .await
        .unwrap();
        let after = chrono::Utc::now().timestamp();
        assert_eq!(created.len(), 1, "one tree file uploaded");
        let inode = created.remove(0);
        model
            .record_created(
                space,
                &inode,
                TreeCreateArgs {
                    parent,
                    name,
                    author: uid,
                    author_name: TREE_TEST_USER_NAME,
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
        inode
    }

    /// `delete_recursive` removes the whole subtree, records every removed id as
    /// deleted, and leaves siblings/ancestors untouched.
    #[test]
    fn delete_recursive_cascades_and_records_deleted() {
        let mut m = FsModel::new();
        m.record_seeded(&folder(1, 0), "u", None);
        m.record_seeded(&folder(2, 1), "u", None);
        m.record_seeded(&file(3, 2), "u", Some(b"x".to_vec()));
        m.record_seeded(&file(4, 0), "u", Some(b"y".to_vec())); // sibling of 1

        m.delete_recursive(1);

        assert_eq!(
            m.live_ids(),
            BTreeSet::from([4]),
            "only the sibling survives"
        );
        assert_eq!(
            m.deleted,
            BTreeSet::from([1, 2, 3]),
            "every removed descendant is recorded as deleted"
        );
    }

    /// The High-severity fix: deleted ids are queried as parents, so a
    /// surviving descendant under a deleted folder (unreachable from root, thus
    /// invisible to the reachability walk) is caught as an unexpected child.
    #[test]
    fn deleted_ids_are_queried_as_parents() {
        let mut m = FsModel::new();
        m.record_seeded(&folder(1, 0), "u", None);
        m.record_seeded(&file(2, 1), "u", Some(b"x".to_vec()));
        m.delete_recursive(1);

        let parents = m.parents_to_query();
        assert!(parents.contains(&1), "deleted folder must be queried");
        assert!(parents.contains(&2), "deleted child must be queried");
    }

    /// Deleting an unknown id is a no-op: nothing is recorded as deleted.
    #[test]
    fn delete_missing_id_is_noop() {
        let mut m = FsModel::new();
        m.record_seeded(&file(5, 0), "u", None);

        m.delete_recursive(999);

        assert_eq!(m.live_ids(), BTreeSet::from([5]));
        assert!(
            m.deleted.is_empty(),
            "deleting an unknown id records nothing as deleted"
        );
    }

    // Exercises move, which emits merk's MRT-only `MovePrefix` write-op.
    #[cfg(feature = "mrt")]
    #[tokio::test]
    async fn tree_fs_model_create_rename_move_delete_list_download() {
        let space = create_tree_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = TreeFsModel::new();

        let projects =
            create_tree_folder_recorded(&space, &mut model, uid, FsHandle::root(), "projects")
                .await;
        let archive =
            create_tree_folder_recorded(&space, &mut model, uid, FsHandle::root(), "archive").await;
        let scratch =
            create_tree_folder_recorded(&space, &mut model, uid, FsHandle::root(), "scratch").await;

        let duplicate_a = upload_tree_file_recorded(
            &space,
            &mut model,
            uid,
            projects.id.clone(),
            "duplicate.txt",
            b"alpha",
        )
        .await;
        let duplicate_b = upload_tree_file_recorded(
            &space,
            &mut model,
            uid,
            projects.id.clone(),
            "duplicate.txt",
            b"beta",
        )
        .await;
        let scratch_file = upload_tree_file_recorded(
            &space,
            &mut model,
            uid,
            scratch.id.clone(),
            "trash.txt",
            b"trash",
        )
        .await;

        assert_tree_matches_model(&space, &model).await;

        let duplicate_listing = files_tree::list_children_tree(&space, projects.id.clone())
            .await
            .unwrap();
        let duplicate_handles: BTreeSet<FsHandle> = duplicate_listing
            .iter()
            .filter(|entry| entry.name == "duplicate.txt")
            .map(|entry| entry.id.clone())
            .collect();
        assert_eq!(
            duplicate_handles,
            BTreeSet::from([duplicate_a.id.clone(), duplicate_b.id.clone()]),
            "duplicate sibling names must both remain addressable by handle"
        );
        assert_eq!(
            files_tree::download_file_tree(&space, duplicate_a.id.clone())
                .await
                .unwrap(),
            b"alpha"
        );
        assert_eq!(
            files_tree::download_file_tree(&space, duplicate_b.id.clone())
                .await
                .unwrap(),
            b"beta"
        );

        let before = chrono::Utc::now().timestamp();
        assert!(
            files_tree::rename_inode_tree(&space, duplicate_a.id.clone(), "alpha-renamed.txt")
                .await
                .unwrap()
        );
        let after = chrono::Utc::now().timestamp();
        model.rename(
            &duplicate_a.id,
            "alpha-renamed.txt",
            TimeExpect::window(before, after),
        );
        assert_tree_matches_model(&space, &model).await;

        let old_projects = projects.id.clone();
        let old_duplicate_b = duplicate_b.id.clone();
        let before = chrono::Utc::now().timestamp();
        let moved = files_tree::move_inode_tree(&space, old_projects.clone(), archive.id.clone())
            .await
            .unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(moved.moved);
        let new_projects = moved.new_id.expect("move must return rebased root handle");
        model.move_subtree(
            &old_projects,
            &new_projects,
            TimeExpect::window(before, after),
        );
        assert_tree_matches_model(&space, &model).await;

        let new_duplicate_b = rebase_tree_handle(&old_duplicate_b, &old_projects, &new_projects)
            .expect("duplicate file should rebase under moved folder");
        assert!(
            files_tree::download_file_tree(&space, old_duplicate_b)
                .await
                .is_err(),
            "pre-move descendant handle must be stale"
        );
        assert_eq!(
            files_tree::download_file_tree(&space, new_duplicate_b)
                .await
                .unwrap(),
            b"beta"
        );

        assert!(
            files_tree::delete_inode_recursive_tree(&space, scratch.id.clone())
                .await
                .unwrap()
        );
        model.delete_recursive(&scratch.id);
        assert_tree_matches_model(&space, &model).await;
        assert!(
            files_tree::download_file_tree(&space, scratch_file.id)
                .await
                .is_err(),
            "deleted descendant handle must not download"
        );

        assert_tree_stale_handle_writes_rejected(&space, &model).await;
    }

    /// A rename that changes the file extension changes the name-derived MIME on
    /// the read surface (deferred MIME — DESIGN §0). The model must track that
    /// (`TreeFsModel::rename` recomputes `mime` from the new name), so the
    /// consistency check still holds after `a.txt` → `a.png`.
    #[tokio::test]
    async fn tree_fs_model_rename_changing_extension_updates_mime() {
        let space = create_tree_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = TreeFsModel::new();

        let file =
            upload_tree_file_recorded(&space, &mut model, uid, FsHandle::root(), "a.txt", b"data")
                .await;
        // Sanity: the read surface starts at the .txt-derived MIME.
        let listing = files_tree::list_children_tree(&space, FsHandle::root())
            .await
            .unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].mime_type, "text/plain");
        assert_tree_matches_model(&space, &model).await;

        // Rename to a .png — the read surface now derives image/png, and the
        // model must expect the new MIME, not the stale text/plain.
        let before = chrono::Utc::now().timestamp();
        assert!(
            files_tree::rename_inode_tree(&space, file.id.clone(), "a.png")
                .await
                .unwrap()
        );
        let after = chrono::Utc::now().timestamp();
        model.rename(&file.id, "a.png", TimeExpect::window(before, after));

        let listing = files_tree::list_children_tree(&space, FsHandle::root())
            .await
            .unwrap();
        assert_eq!(listing[0].name, "a.png");
        assert_eq!(listing[0].mime_type, "image/png");
        assert_tree_matches_model(&space, &model).await;
    }
}
