//! Relative-inode ("tree") filesystem backend (prototype).
//!
//! See [`docs/native_ops_plans/PLAN_FS_TEST.md`](../../../../docs/native_ops_plans/PLAN_FS_TEST.md).
//!
//! This module holds the Stage T0 [`codec`], the Stage T1 Tauri-shaped helper
//! API, and the Stage T2 [`FsHandleWire`] wire contract that the serialized
//! handle Tauri commands speak. Writes go through the SDK's native tree-FS ops;
//! reads use raw point/prefix reads over the changelog keys.

pub mod codec;

use anyhow::{anyhow, Result};
use encrypted_spaces_sdk::native_op::FsHandleWireCodec;
use encrypted_spaces_sdk::{native_op as sdk_tree_fs, tree_fs as core_tree_fs, File, Space};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::chat::UsersMeta;
use crate::files::{
    download_file_by_hash, mime_from_extension, PendingFile, INODE_FILE, INODE_FOLDER,
};

/// Hierarchical filesystem handle: the root-to-node chain of 256-bit inode ids.
/// The root is `FsHandle(vec![])`.
///
/// On the wire (Tauri command / frontend) this serializes as its
/// [`FsHandleWire`] form — a JSON array of 64-char hex inode ids, with the root
/// rendered as the empty array `[]`. This is the breaking K4 `FsHandleWire`
/// contract in `PLAN_TREE_FS_KEYMODEL.md`, replacing the Stage T2 `Vec<u32>`
/// label array.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "FsHandleWire", into = "FsHandleWire")]
pub struct FsHandle(pub Vec<core_tree_fs::InodeId>);

/// Wire (Tauri command / frontend) representation of an [`FsHandle`]: a JSON
/// array of 64-char hex inode ids, with the root rendered as the empty array
/// `[]`. Mirrors the SDK's [`sdk_tree_fs::FsHandleWire`].
pub type FsHandleWire = Vec<String>;

impl FsHandle {
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Build a handle from its wire form (a list of 64-char hex inode ids),
    /// hex-decoding and validating each id, as received from a Tauri command.
    /// The empty array is the root handle; a malformed component is an error.
    pub fn from_wire(wire: FsHandleWire) -> Result<Self> {
        Ok(Self(sdk_tree_fs::FsHandle::from_wire(wire)?))
    }

    /// Consume the handle into its owned wire form (hex inode ids) for returning
    /// over a Tauri command boundary.
    pub fn into_wire(self) -> FsHandleWire {
        self.0.into_wire()
    }
}

impl From<FsHandle> for FsHandleWire {
    fn from(handle: FsHandle) -> Self {
        handle.into_wire()
    }
}

impl TryFrom<FsHandleWire> for FsHandle {
    type Error = anyhow::Error;

    fn try_from(wire: FsHandleWire) -> Result<Self> {
        Self::from_wire(wire)
    }
}

/// Tree-backend inode shape. It mirrors `files::Inode` where possible but uses
/// hierarchical handles instead of table row ids.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeInode {
    pub id: FsHandle,
    pub parent_id: FsHandle,
    pub author_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub inode_type: i64,
    pub size: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub mime_type: String,
    pub file_hash: File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeInodeWithAuthor {
    pub id: FsHandle,
    pub parent_id: FsHandle,
    pub author_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub inode_type: i64,
    pub size: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub mime_type: String,
    pub file_hash: File,
    pub author_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveInodeResult {
    pub moved: bool,
    pub new_id: Option<FsHandle>,
}

/// Upload files as tree-FS file nodes under `parent`.
pub async fn upload_files_tree(
    space: &Space,
    parent: FsHandle,
    author_id: i64,
    files: Vec<PendingFile>,
) -> Result<Vec<TreeInode>> {
    let author_uid = author_to_u32(author_id)?;
    let ts = chrono::Utc::now().timestamp();
    let mut out = Vec::new();

    for file in files {
        let size = file.data.len() as i64;
        let name = file.filename;
        let uploaded = space.file().upload(File::from_data(file.data)).await?;
        let id = space
            .submit_tree_fs_create_native(
                parent.0.clone(),
                author_uid,
                core_tree_fs::NodeKind::File,
                name.as_bytes().to_vec(),
                u64::try_from(size).map_err(|_| anyhow!("file size {size} is negative"))?,
                ts,
                ts,
                content_hash_from_file(&uploaded)?,
            )
            .await?;
        // The codec does not persist a MIME (deferred — DESIGN §0); the read
        // surface derives it from the name, so the returned inode reports the
        // same derived MIME, not the requested `file.mime_type`.
        let mime_type = mime_from_extension(&name);
        out.push(TreeInode {
            id: FsHandle(id),
            parent_id: parent.clone(),
            author_id,
            name,
            inode_type: INODE_FILE,
            size,
            ctime: ts,
            mtime: ts,
            mime_type,
            file_hash: uploaded,
        });
    }

    Ok(out)
}

/// Create a tree-FS folder under `parent`.
pub async fn create_folder_tree(
    space: &Space,
    parent: FsHandle,
    author_id: i64,
    name: &str,
) -> Result<TreeInode> {
    let ts = chrono::Utc::now().timestamp();
    let file_hash = File::from_hash(folder_hash_hex());
    let id = space
        .submit_tree_fs_create_native(
            parent.0.clone(),
            author_to_u32(author_id)?,
            core_tree_fs::NodeKind::Directory,
            name.as_bytes().to_vec(),
            0,
            ts,
            ts,
            content_hash_from_file(&file_hash)?,
        )
        .await?;
    Ok(TreeInode {
        id: FsHandle(id),
        parent_id: parent,
        author_id,
        name: name.to_string(),
        inode_type: INODE_FOLDER,
        size: 0,
        ctime: ts,
        mtime: ts,
        mime_type: String::new(),
        file_hash,
    })
}

/// List direct children of a tree-FS directory with author display names.
pub async fn list_children_tree(
    space: &Space,
    parent: FsHandle,
) -> Result<Vec<TreeInodeWithAuthor>> {
    // Validate the parent is a directory. The root (`[]`) is an implicit
    // directory with no record of its own, so an empty root simply lists `[]`.
    if !parent.0.is_empty() {
        let parent_inode = read_node_inode(space, &parent.0)
            .await?
            .ok_or_else(|| anyhow!("tree filesystem parent {:?} not found", parent.0))?;
        if parent_inode.kind()? != codec::NodeKind::Directory {
            return Err(anyhow!(
                "tree filesystem parent {:?} is not a directory",
                parent.0
            ));
        }
    }

    // One-level listing: scan `CONTAINER(parent) || /info`, which matches only
    // the parent's direct child records (a grandchild's key threads through
    // `/dir` before its own `/info`, so it cannot share this prefix). No
    // client-side depth filter is needed.
    let prefix = codec::encode_children_listing_prefix(&parent.0)?;
    let author_names = author_name_map(space).await?;
    let mut out = Vec::new();
    for (key, value) in space.raw_read_prefix(prefix).await? {
        let Ok(path) = codec::decode_record_key::<codec::InodePath>(&key) else {
            continue;
        };
        let record = codec::Inode::decode(&value)?;
        let inode = tree_inode_from_codec(path, parent.clone(), record)?;
        let author_name = author_names
            .get(&inode.author_id)
            .cloned()
            .unwrap_or_else(|| format!("user_{}", inode.author_id));
        out.push(TreeInodeWithAuthor {
            id: inode.id,
            parent_id: inode.parent_id,
            author_id: inode.author_id,
            name: inode.name,
            inode_type: inode.inode_type,
            size: inode.size,
            ctime: inode.ctime,
            mtime: inode.mtime,
            mime_type: inode.mime_type,
            file_hash: inode.file_hash,
            author_name,
        });
    }

    out.sort_by(|a, b| {
        a.inode_type
            .cmp(&b.inode_type)
            .reverse()
            .then_with(|| b.ctime.cmp(&a.ctime))
    });
    Ok(out)
}

pub async fn rename_inode_tree(space: &Space, id: FsHandle, new_name: &str) -> Result<bool> {
    let ts = chrono::Utc::now().timestamp();
    let updated = space
        .submit_tree_fs_rename_native(id.0, new_name.as_bytes().to_vec(), ts)
        .await?;
    Ok(updated > 0)
}

pub async fn move_inode_tree(
    space: &Space,
    id: FsHandle,
    new_parent: FsHandle,
) -> Result<MoveInodeResult> {
    let ts = chrono::Utc::now().timestamp();
    let new_id = space
        .submit_tree_fs_move_native(id.0, new_parent.0, ts)
        .await?
        .map(FsHandle);
    Ok(MoveInodeResult {
        moved: new_id.is_some(),
        new_id,
    })
}

pub async fn delete_inode_recursive_tree(space: &Space, id: FsHandle) -> Result<bool> {
    let deleted = space.submit_tree_fs_delete_native(id.0).await?;
    Ok(deleted > 0)
}

pub async fn download_file_tree(space: &Space, id: FsHandle) -> Result<Vec<u8>> {
    let inode = read_node_inode(space, &id.0)
        .await?
        .ok_or_else(|| anyhow!("tree filesystem node {:?} not found", id.0))?;
    if inode.kind()? != codec::NodeKind::File {
        return Err(anyhow!("tree filesystem node {:?} is not a file", id.0));
    }
    let hash = hex::encode(inode.content_hash);
    download_file_by_hash(space, &hash).await
}

async fn read_node_inode(
    space: &Space,
    path: &[core_tree_fs::InodeId],
) -> Result<Option<codec::Inode>> {
    let key = codec::encode_record_key(path)?;
    space
        .raw_read_key(key)
        .await?
        .map(|bytes| codec::Inode::decode(&bytes).map_err(Into::into))
        .transpose()
}

fn tree_inode_from_codec(
    path: Vec<core_tree_fs::InodeId>,
    parent: FsHandle,
    inode: codec::Inode,
) -> Result<TreeInode> {
    let kind = inode.kind()?;
    let inode_type = match kind {
        codec::NodeKind::File => INODE_FILE,
        codec::NodeKind::Directory => INODE_FOLDER,
    };
    let name = String::from_utf8(inode.name).map_err(|e| anyhow!("name is not utf8: {e}"))?;
    // Deferred MIME (DESIGN §0): not stored, derived from the name for files;
    // folders carry no MIME.
    let mime_type = match kind {
        codec::NodeKind::File => mime_from_extension(&name),
        codec::NodeKind::Directory => String::new(),
    };
    let file_hash = File::from_hash(hex::encode(inode.content_hash));
    Ok(TreeInode {
        id: FsHandle(path),
        parent_id: parent,
        author_id: i64::from(inode.author_uid),
        name,
        inode_type,
        size: i64::try_from(inode.size)
            .map_err(|_| anyhow!("inode size {} exceeds i64", inode.size))?,
        ctime: inode.ctime,
        mtime: inode.mtime,
        mime_type,
        file_hash,
    })
}

async fn author_name_map(space: &Space) -> Result<BTreeMap<i64, String>> {
    let users: Vec<UsersMeta> = space
        .table::<UsersMeta>("users_meta")
        .select()
        .all()
        .await?;
    Ok(users
        .into_iter()
        .filter_map(|user| user.id.map(|id| (id, user.name)))
        .collect())
}

fn author_to_u32(author_id: i64) -> Result<u32> {
    u32::try_from(author_id).map_err(|_| anyhow!("author_id {author_id} does not fit u32"))
}

fn content_hash_from_file(file: &File) -> Result<[u8; core_tree_fs::CONTENT_HASH_LEN]> {
    sdk_tree_fs::tree_fs_content_hash_from_hex(file.hash()?).map_err(Into::into)
}

fn folder_hash_hex() -> String {
    "0".repeat(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport};

    const TEST_USER_NAME: &str = "test_user";
    const TEST_SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../app_schema.kdl");

    async fn create_test_space() -> (LocalTransport, Space) {
        std::env::set_var("RISC0_DEV_MODE", "1");
        let transport = LocalTransport::from_schema_file(TEST_SCHEMA_PATH)
            .await
            .unwrap();
        let commitment = transport.get_root_hash().await.unwrap();
        let space = Space::create(
            transport.clone(),
            ApplicationSchema::for_testing_from_bytes(crate::APP_SCHEMA_BYTES, commitment),
        )
        .await
        .unwrap();
        let uid = space.get_auth_context().uid.unwrap();
        crate::chat::set_user_name(&space, uid, TEST_USER_NAME)
            .await
            .unwrap();
        (transport, space)
    }

    fn pending(name: &str, mime: &str, data: &[u8]) -> PendingFile {
        PendingFile {
            data: data.to_vec(),
            filename: name.to_string(),
            mime_type: mime.to_string(),
        }
    }

    /// A fresh space's root (`[]`) is an implicit directory with no record of
    /// its own, so listing it returns `[]` rather than erroring on a missing
    /// parent record.
    #[tokio::test]
    async fn tree_fs_list_empty_root_returns_empty() {
        let (_transport, space) = create_test_space().await;
        let listing = list_children_tree(&space, FsHandle::root()).await.unwrap();
        assert!(listing.is_empty());
    }

    #[tokio::test]
    async fn tree_fs_create_file_roundtrip() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let data = b"hello tree".to_vec();

        let created = upload_files_tree(
            &space,
            FsHandle::root(),
            uid,
            vec![pending("notes.txt", "text/plain", &data)],
        )
        .await
        .unwrap();

        assert_eq!(created.len(), 1);
        // The id is an inode-id chain derived from the parent CLC, not a label;
        // a root child is one id deep.
        assert_eq!(created[0].id.0.len(), 1);
        let listing = list_children_tree(&space, FsHandle::root()).await.unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].id, created[0].id);
        assert_eq!(listing[0].name, "notes.txt");
        assert_eq!(listing[0].inode_type, INODE_FILE);
        assert_eq!(listing[0].size, data.len() as i64);
        assert_eq!(listing[0].mime_type, "text/plain");
        assert_eq!(listing[0].author_name, TEST_USER_NAME);
    }

    #[tokio::test]
    async fn tree_fs_create_folder_roundtrip() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();

        let folder = create_folder_tree(&space, FsHandle::root(), uid, "projects")
            .await
            .unwrap();

        assert_eq!(folder.id.0.len(), 1);
        let listing = list_children_tree(&space, FsHandle::root()).await.unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].id, folder.id);
        assert_eq!(listing[0].name, "projects");
        assert_eq!(listing[0].inode_type, INODE_FOLDER);
    }

    #[tokio::test]
    async fn tree_fs_download_file_roundtrip() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let data = b"download me".to_vec();

        let file = upload_files_tree(
            &space,
            FsHandle::root(),
            uid,
            vec![pending("download.txt", "text/plain", &data)],
        )
        .await
        .unwrap()
        .remove(0);

        let by_handle = download_file_tree(&space, file.id).await.unwrap();
        assert_eq!(by_handle, data);
        let by_hash = download_file_by_hash(&space, file.file_hash.hash().unwrap())
            .await
            .unwrap();
        assert_eq!(by_hash, data);
    }

    // Move emits merk's `MovePrefix` write-op, which only the MRT backend
    // supports (AVL handles reject it with `Unsupported`).
    #[cfg(feature = "mrt")]
    #[tokio::test]
    async fn tree_fs_move_returns_rebased_handle() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let projects = create_folder_tree(&space, FsHandle::root(), uid, "projects")
            .await
            .unwrap();
        let archive = create_folder_tree(&space, FsHandle::root(), uid, "archive")
            .await
            .unwrap();
        let data = b"inside".to_vec();
        let child = upload_files_tree(
            &space,
            projects.id.clone(),
            uid,
            vec![pending("child.txt", "text/plain", &data)],
        )
        .await
        .unwrap()
        .remove(0);
        // `child` hangs off `projects`: [projects_id, child_id].
        assert_eq!(child.id.0.len(), 2);
        assert_eq!(child.id.0[0], projects.id.0[0]);

        let moved = move_inode_tree(&space, projects.id.clone(), archive.id.clone())
            .await
            .unwrap();

        assert!(moved.moved);
        let new_projects = moved.new_id.unwrap();
        // The moved folder keeps its own inode id but rebases under `archive`.
        assert_eq!(new_projects.0.len(), 2);
        assert_eq!(new_projects.0[0], archive.id.0[0]);
        assert_eq!(new_projects.0[1], projects.id.0[0]);
        // The pre-move descendant handle is stale; the child is reachable at its
        // rebased handle (new_projects ++ [child's own id]).
        assert!(download_file_tree(&space, child.id.clone()).await.is_err());
        let new_child = FsHandle({
            let mut path = new_projects.0.clone();
            path.push(child.id.0[1]);
            path
        });
        assert_eq!(download_file_tree(&space, new_child).await.unwrap(), data);
    }

    #[tokio::test]
    async fn tree_fs_removed_user_write_rejected() {
        let (transport, alice) = create_test_space().await;
        let bob_invite = alice.invite_user().await.unwrap();
        let bob = Space::join(
            transport.clone(),
            bob_invite,
            ApplicationSchema::for_testing_from_bytes(
                crate::APP_SCHEMA_BYTES,
                transport.get_root_hash().await.unwrap(),
            ),
        )
        .await
        .unwrap();
        let bob_uid = bob.get_auth_context().uid.unwrap();
        crate::chat::set_user_name(&bob, bob_uid, "bob")
            .await
            .unwrap();
        alice.sync().await.unwrap();

        alice.remove_user(bob_uid).await.unwrap();
        let _ = bob.sync().await;

        let err = create_folder_tree(&bob, FsHandle::root(), bob_uid, "should-fail")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Access denied")
                || msg.contains("ACL denied")
                || msg.contains("auth_key not found for uid"),
            "expected removed-user access rejection, got {msg}"
        );
    }

    // ─── Stage T2: serialized-handle (Tauri wire) tests ───────────────────────

    /// `FsHandle`, `TreeInode`, and `MoveInodeResult` round-trip through the K4
    /// `FsHandleWire = string[]` JSON contract the Tauri commands speak: handles
    /// are arrays of 64-char hex inode ids, the root is `[]`, and `file_hash`
    /// stays a content-hash string (the unchanged `download_file_by_hash` path).
    #[test]
    fn tree_fs_tauri_handle_wire_roundtrip() {
        use serde_json::json;

        let id_a = [0xAB; core_tree_fs::INODE_ID_LEN];
        let id_b = [0xCD; core_tree_fs::INODE_ID_LEN];
        let hex_a = hex::encode(id_a);
        let hex_b = hex::encode(id_b);

        // FsHandle <-> FsHandleWire conversions (hex inode ids).
        let wire: FsHandleWire = vec![hex_a.clone(), hex_b.clone()];
        let handle = FsHandle::from_wire(wire.clone()).unwrap();
        assert_eq!(handle, FsHandle(vec![id_a, id_b]));
        assert_eq!(handle.into_wire(), wire);
        // Malformed components (odd hex / wrong length / zero id) are rejected.
        assert!(FsHandle::from_wire(vec!["f".to_string()]).is_err());
        assert!(FsHandle::from_wire(vec!["00".repeat(core_tree_fs::INODE_ID_LEN)]).is_err());

        // Root is the empty array on the wire.
        assert_eq!(FsHandle::root().into_wire(), Vec::<String>::new());
        assert_eq!(serde_json::to_value(FsHandle::root()).unwrap(), json!([]));

        // FsHandle serializes as a JSON array of hex inode ids.
        assert_eq!(
            serde_json::to_value(FsHandle(vec![id_a, id_b])).unwrap(),
            json!([hex_a, hex_b])
        );
        let back: FsHandle = serde_json::from_value(json!([hex_a, hex_b])).unwrap();
        assert_eq!(back, FsHandle(vec![id_a, id_b]));

        // TreeInode.id / parent_id serialize as FsHandleWire arrays; root is [].
        let inode = TreeInode {
            id: FsHandle(vec![id_a]),
            parent_id: FsHandle::root(),
            author_id: 7,
            name: "notes.txt".to_string(),
            inode_type: INODE_FILE,
            size: 11,
            ctime: 100,
            mtime: 100,
            mime_type: "text/plain".to_string(),
            file_hash: File::from_hash("0".repeat(64)),
        };
        let value = serde_json::to_value(&inode).unwrap();
        assert_eq!(value["id"], json!([hex_a]));
        assert_eq!(value["parent_id"], json!([]));
        assert_eq!(value["file_hash"], json!("0".repeat(64)));
        let decoded: TreeInode = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.id, inode.id);
        assert_eq!(decoded.parent_id, inode.parent_id);
        assert_eq!(decoded.name, inode.name);
        assert_eq!(
            decoded.file_hash.hash().unwrap(),
            inode.file_hash.hash().unwrap()
        );

        // MoveInodeResult serializes new_id as a hex array, or null when absent.
        let moved = MoveInodeResult {
            moved: true,
            new_id: Some(FsHandle(vec![id_b, id_a])),
        };
        assert_eq!(
            serde_json::to_value(&moved).unwrap(),
            json!({ "moved": true, "new_id": [hex_b, hex_a] })
        );
        let not_moved = MoveInodeResult {
            moved: false,
            new_id: None,
        };
        assert_eq!(
            serde_json::to_value(&not_moved).unwrap(),
            json!({ "moved": false, "new_id": null })
        );
    }

    /// The root handle `[]` (as it arrives from the frontend) creates and lists
    /// root children through the same helper path the Tauri command calls, and
    /// children report the root parent as `[]` on the wire.
    #[tokio::test]
    async fn tree_fs_tauri_root_handle_lists_root() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();

        // Root handle exactly as a Tauri command would deserialize it.
        let root = FsHandle::from_wire(Vec::new()).unwrap();
        create_folder_tree(&space, root.clone(), uid, "projects")
            .await
            .unwrap();
        upload_files_tree(
            &space,
            root.clone(),
            uid,
            vec![pending("notes.txt", "text/plain", b"hi")],
        )
        .await
        .unwrap();

        let listing = list_children_tree(&space, FsHandle::from_wire(Vec::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(listing.len(), 2);
        // Folders sort before files; both hang directly off the root handle.
        assert_eq!(listing[0].name, "projects");
        assert_eq!(listing[1].name, "notes.txt");
        for child in &listing {
            assert_eq!(child.parent_id, FsHandle::root());
        }

        // The wire-serialized listing reports the root parent as `[]`.
        let value = serde_json::to_value(&listing).unwrap();
        assert_eq!(value[0]["parent_id"], serde_json::json!([]));
    }

    /// A successful move returns `MoveInodeResult { moved: true, new_id }` with
    /// the moved root's rebased handle, and that result serializes for the
    /// frontend with `new_id` as a handle array.
    #[cfg(feature = "mrt")]
    #[tokio::test]
    async fn tree_fs_tauri_move_returns_new_handle() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let projects = create_folder_tree(&space, FsHandle::root(), uid, "projects")
            .await
            .unwrap();
        let archive = create_folder_tree(&space, FsHandle::root(), uid, "archive")
            .await
            .unwrap();
        assert_eq!(projects.id.0.len(), 1);
        assert_eq!(archive.id.0.len(), 1);

        let result = move_inode_tree(&space, projects.id.clone(), archive.id.clone())
            .await
            .unwrap();

        assert!(result.moved);
        // The moved folder rebases under `archive` but keeps its own inode id.
        let expected_new = FsHandle(vec![archive.id.0[0], projects.id.0[0]]);
        assert_eq!(result.new_id, Some(expected_new.clone()));

        // Serializes for the frontend as a hex handle array.
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "moved": true,
                "new_id": [hex::encode(archive.id.0[0]), hex::encode(projects.id.0[0])],
            })
        );

        // The moved folder is reachable at its new handle and gone from root.
        let new_handle = FsHandle::from_wire(result.new_id.unwrap().into_wire()).unwrap();
        let listing = list_children_tree(&space, new_handle).await.unwrap();
        assert!(listing.is_empty());
        let root_listing = list_children_tree(&space, FsHandle::root()).await.unwrap();
        let root_names: Vec<&str> = root_listing.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(root_names, vec!["archive"]);
    }

    /// After a move, the stale pre-move handle (and stale descendant handles)
    /// cannot download, rename, move, or delete the moved nodes; the moved
    /// subtree stays intact at its new handle.
    #[cfg(feature = "mrt")]
    #[tokio::test]
    async fn tree_fs_tauri_stale_handle_rejected() {
        let (_transport, space) = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let projects = create_folder_tree(&space, FsHandle::root(), uid, "projects")
            .await
            .unwrap();
        let archive = create_folder_tree(&space, FsHandle::root(), uid, "archive")
            .await
            .unwrap();
        let data = b"inside".to_vec();
        let child = upload_files_tree(
            &space,
            projects.id.clone(),
            uid,
            vec![pending("child.txt", "text/plain", &data)],
        )
        .await
        .unwrap()
        .remove(0);
        assert_eq!(projects.id.0.len(), 1);
        assert_eq!(child.id.0.len(), 2);

        let result = move_inode_tree(&space, projects.id.clone(), archive.id.clone())
            .await
            .unwrap();
        let new_projects = FsHandle(vec![archive.id.0[0], projects.id.0[0]]);
        assert_eq!(result.new_id, Some(new_projects.clone()));
        let new_child = FsHandle(vec![archive.id.0[0], projects.id.0[0], child.id.0[1]]);

        // Stale handles for the moved subtree no longer resolve.
        let stale_root = projects.id.clone(); // [1]
        let stale_child = child.id.clone(); // [1, 1]

        // download: missing record -> error.
        assert!(download_file_tree(&space, stale_child.clone())
            .await
            .is_err());

        // rename: no-op (0 rows) -> false, and must not touch the moved node.
        assert!(!rename_inode_tree(&space, stale_root.clone(), "renamed")
            .await
            .unwrap());

        // move: no source record -> not moved, no new handle.
        let stale_move = move_inode_tree(&space, stale_root.clone(), FsHandle::root())
            .await
            .unwrap();
        assert!(!stale_move.moved);
        assert!(stale_move.new_id.is_none());

        // delete: no-op (0 rows) -> false.
        assert!(!delete_inode_recursive_tree(&space, stale_root.clone())
            .await
            .unwrap());

        // The moved subtree is untouched at its new handle: name preserved and
        // bytes still downloadable.
        let archive_listing = list_children_tree(&space, archive.id.clone())
            .await
            .unwrap();
        assert_eq!(archive_listing.len(), 1);
        assert_eq!(archive_listing[0].name, "projects");
        assert_eq!(archive_listing[0].id, new_projects);
        assert_eq!(download_file_tree(&space, new_child).await.unwrap(), data);
    }
}
