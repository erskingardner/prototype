use anyhow::Result;
use encrypted_spaces_sdk::{File, Space};
use serde::{Deserialize, Serialize};

use crate::sdk_codegen::Actions;

// ─── Inode types ─────────────────────────────────────────────────────────────

/// Inode types stored in the `type` column.
pub const INODE_FILE: i64 = 1;
pub const INODE_FOLDER: i64 = 2;

/// Map a filename to a MIME type from its extension.
///
/// The table backend stores this at upload time; the tree backend does not
/// persist a MIME (deferred — see
/// `docs/native_ops_plans/DESIGN_TREE_FS_KEY_MODEL.md` §0) and derives it
/// client-side from the name on every read, so both backends and the
/// reference model share this one mapping.
pub fn mime_from_extension(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "gz" | "tar" => "application/gzip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// The core inode struct matching the `inodes` table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub id: Option<i64>,
    pub parent_id: i64,
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

/// Joined result of inode + users_meta (for author display name).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeWithAuthor {
    pub id: Option<i64>,
    pub parent_id: i64,
    pub author_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub inode_type: i64,
    pub size: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub mime_type: String,
    pub file_hash: File,
    /// Author display name from users_meta join.
    pub author_name: String,
}

/// Deserialized from the join query (users_meta.name comes back as "name" which
/// conflicts with inodes.name, so we select explicit columns with table prefixes).
#[derive(Debug, Deserialize)]
struct InodeJoined {
    id: Option<i64>,
    parent_id: i64,
    author_id: i64,
    name: String,
    #[serde(rename = "type")]
    inode_type: i64,
    size: i64,
    ctime: i64,
    mtime: i64,
    mime_type: String,
    file_hash: File,
    #[serde(rename = "author_name")]
    author_name: String,
}

/// A file to be uploaded (before encryption/storage).
pub struct PendingFile {
    pub data: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
}

// ─── CRUD operations ─────────────────────────────────────────────────────────

/// Upload files as inodes under the given parent_id.
pub async fn upload_files(
    space: &Space,
    parent_id: i64,
    author_id: i64,
    files: Vec<PendingFile>,
) -> Result<Vec<Inode>> {
    let handle = space.file();
    let ts = chrono::Utc::now().timestamp();
    let mut result = Vec::new();

    for file in files {
        let size = file.data.len() as i64;
        let file_hash = handle.upload(File::from_data(file.data)).await?;
        let entry = Inode {
            id: None,
            parent_id,
            author_id,
            name: file.filename,
            inode_type: INODE_FILE,
            size,
            ctime: ts,
            mtime: ts,
            mime_type: file.mime_type,
            file_hash,
        };
        let id = space.add_inode(&entry).await?;
        result.push(Inode {
            id: Some(id),
            ..entry
        });
    }

    Ok(result)
}

/// Create a folder inode under the given parent_id.
pub async fn create_folder(
    space: &Space,
    parent_id: i64,
    author_id: i64,
    name: &str,
) -> Result<Inode> {
    let ts = chrono::Utc::now().timestamp();
    let entry = Inode {
        id: None,
        parent_id,
        author_id,
        name: name.to_string(),
        inode_type: INODE_FOLDER,
        size: 0,
        ctime: ts,
        mtime: ts,
        mime_type: String::new(),
        file_hash: File::from_hash("0".repeat(64)),
    };
    let id = space.add_inode(&entry).await?;
    Ok(Inode {
        id: Some(id),
        ..entry
    })
}

/// List inodes directly under a parent, with author names, newest first.
pub async fn list_children(space: &Space, parent_id: i64) -> Result<Vec<InodeWithAuthor>> {
    let joined: Vec<InodeJoined> = space
        .table::<Inode>("inodes")
        .select()
        .columns(&[
            "inodes.id",
            "inodes.parent_id",
            "inodes.author_id",
            "inodes.name",
            "inodes.type",
            "inodes.size",
            "inodes.ctime",
            "inodes.mtime",
            "inodes.mime_type",
            "inodes.file_hash",
            "users_meta.name as author_name",
        ])
        .where_eq("parent_id", parent_id)
        .join("users_meta", "author_id", "id")
        .all_as()
        .await?;

    let mut result: Vec<InodeWithAuthor> = joined
        .into_iter()
        .map(|j| InodeWithAuthor {
            id: j.id,
            parent_id: j.parent_id,
            author_id: j.author_id,
            name: j.name,
            inode_type: j.inode_type,
            size: j.size,
            ctime: j.ctime,
            mtime: j.mtime,
            mime_type: j.mime_type,
            file_hash: j.file_hash,
            author_name: j.author_name,
        })
        .collect();

    // Folders first (type 2), then files (type 1); within each group newest first.
    result.sort_by(|a, b| {
        a.inode_type
            .cmp(&b.inode_type)
            .reverse()
            .then_with(|| b.ctime.cmp(&a.ctime))
    });

    Ok(result)
}

/// Recursively delete an inode and all descendants.
pub async fn delete_inode_recursive(space: &Space, inode_id: i64) -> Result<bool> {
    // First, recursively delete all children
    let children: Vec<Inode> = space
        .table::<Inode>("inodes")
        .select()
        .where_eq("parent_id", inode_id)
        .all()
        .await?;

    for child in children {
        if let Some(child_id) = child.id {
            Box::pin(delete_inode_recursive(space, child_id)).await?;
        }
    }

    // Then delete the inode itself
    let deleted = space
        .table::<Inode>("inodes")
        .delete()
        .where_eq("id", inode_id)
        .execute()
        .await?;
    Ok(deleted > 0)
}

/// Move an inode to a new parent.
pub async fn move_inode(space: &Space, inode_id: i64, new_parent_id: i64) -> Result<bool> {
    let ts = chrono::Utc::now().timestamp();
    let updated = space
        .move_inode(inode_id)
        .parent_id(new_parent_id)
        .mtime(ts)
        .execute()
        .await?;
    Ok(updated > 0)
}

/// Rename an inode.
pub async fn rename_inode(space: &Space, inode_id: i64, new_name: &str) -> Result<bool> {
    let ts = chrono::Utc::now().timestamp();
    let updated = space
        .rename_inode(inode_id)
        .name(new_name.to_string())
        .mtime(ts)
        .execute()
        .await?;
    Ok(updated > 0)
}

/// Download and decrypt a file blob by its content hash.
///
/// Shared by the Tauri `download_file` command (after a disk-cache miss)
/// and the test harness, so both go through the same SDK call path.
pub async fn download_file_by_hash(space: &Space, hash: &str) -> Result<Vec<u8>> {
    let downloaded = space
        .file()
        .download(&File::from_hash(hash.to_string()))
        .await?;
    Ok(downloaded.into_data()?)
}

/// Look up a file inode by id and download its decrypted bytes.
pub async fn download_file(space: &Space, inode_id: i64) -> Result<Vec<u8>> {
    let inode = space
        .table::<Inode>("inodes")
        .select()
        .where_eq("id", inode_id)
        .first()
        .await?
        .ok_or_else(|| anyhow::anyhow!("inode {inode_id} not found"))?;
    download_file_by_hash(space, inode.file_hash.hash()?).await
}

#[cfg(test)]
mod fs_tests {
    //! Self-consistent filesystem tests for the `files` verb surface
    //! (see `docs/native_ops_plans/PLAN_FS_TEST.md`). Stage T1 lands the
    //! fixture (`create_test_space`), the reference model + checker
    //! ([`crate::fs_test_model`]), and one round-trip (`create_file_roundtrip`)
    //! proving the infrastructure works against the current
    //! (data-driven write + `SELECT` read) surface.

    use super::*;
    use crate::fs_test_model::{
        assert_matches_model, CreateArgs, FsModel, TimeExpect, FOLDER_HASH_HEX,
    };
    use crate::sdk_codegen::Actions;
    use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport};
    use std::collections::BTreeMap;

    /// The display name `create_test_space` records for the founding user in
    /// `users_meta`; `list_children`'s author join must report it.
    const TEST_USER_NAME: &str = "test_user";
    const TEST_SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../app_schema.kdl");

    /// Single-space fixture, copied from
    /// [`crate::chat`]'s `create_test_space` test helper: a fresh
    /// `LocalTransport` with the full demo app schema bundle imported, one
    /// founding user whose `users_meta` name is [`TEST_USER_NAME`].
    async fn create_test_space() -> Space {
        std::env::set_var("RISC0_DEV_MODE", "1"); // Tests always use dev mode
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

        // Insert a `users_meta` row for the creator so the author-name join in
        // `list_children` resolves.
        let uid = space.get_auth_context().uid.unwrap();
        crate::chat::set_user_name(&space, uid, TEST_USER_NAME)
            .await
            .unwrap();

        space
    }

    fn pending(name: &str, mime: &str, data: &[u8]) -> PendingFile {
        PendingFile {
            data: data.to_vec(),
            filename: name.to_string(),
            mime_type: mime.to_string(),
        }
    }

    fn inode_id(inode: &Inode) -> i64 {
        inode.id.expect("test inode must have an id")
    }

    fn zero_hash() -> File {
        File::from_hash("0".repeat(64))
    }

    fn synthetic_hash(seed: u8) -> File {
        File::from_hash(format!("{seed:02x}").repeat(32))
    }

    async fn create_folder_recorded(
        space: &Space,
        model: &mut FsModel,
        uid: i64,
        parent_id: i64,
        name: &str,
    ) -> Inode {
        let before = chrono::Utc::now().timestamp();
        let inode = create_folder(space, parent_id, uid, name).await.unwrap();
        let after = chrono::Utc::now().timestamp();
        model.record_created(
            &inode,
            CreateArgs {
                parent: parent_id,
                name,
                author: uid,
                author_name: TEST_USER_NAME,
                inode_type: INODE_FOLDER,
                size: 0,
                mime: "",
                file_hash: Some(FOLDER_HASH_HEX),
                bytes: None,
                ctime: TimeExpect::window(before, after),
                mtime: TimeExpect::window(before, after),
            },
        );
        inode
    }

    async fn upload_file_recorded(
        space: &Space,
        model: &mut FsModel,
        uid: i64,
        parent_id: i64,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Inode {
        let before = chrono::Utc::now().timestamp();
        let mut created = upload_files(space, parent_id, uid, vec![pending(name, mime, data)])
            .await
            .unwrap();
        let after = chrono::Utc::now().timestamp();
        assert_eq!(created.len(), 1, "one file uploaded");
        let inode = created.remove(0);
        model.record_created(
            &inode,
            CreateArgs {
                parent: parent_id,
                name,
                author: uid,
                author_name: TEST_USER_NAME,
                inode_type: INODE_FILE,
                size: data.len() as i64,
                mime,
                file_hash: None,
                bytes: Some(data.to_vec()),
                ctime: TimeExpect::window(before, after),
                mtime: TimeExpect::window(before, after),
            },
        );
        inode
    }

    async fn seed_folder_recorded(
        space: &Space,
        model: &mut FsModel,
        uid: i64,
        parent_id: i64,
        name: &str,
        ctime: i64,
        mtime: i64,
    ) -> Inode {
        let mut inode = Inode {
            id: None,
            parent_id,
            author_id: uid,
            name: name.to_string(),
            inode_type: INODE_FOLDER,
            size: 0,
            ctime,
            mtime,
            mime_type: String::new(),
            file_hash: zero_hash(),
        };
        let id = space.add_inode(&inode).await.unwrap();
        inode.id = Some(id);
        model.record_seeded(&inode, TEST_USER_NAME, None);
        inode
    }

    // A seed helper that mirrors every controllable `Inode` column; the wide
    // signature is inherent to exercising full field coverage from a test.
    #[allow(clippy::too_many_arguments)]
    async fn seed_file_recorded(
        space: &Space,
        model: &mut FsModel,
        uid: i64,
        parent_id: i64,
        name: &str,
        mime: &str,
        size: i64,
        bytes: Option<Vec<u8>>,
        hash_seed: u8,
        ctime: i64,
        mtime: i64,
    ) -> Inode {
        let (size, file_hash) = match &bytes {
            Some(data) => {
                let hash = space
                    .file()
                    .upload(File::from_data(data.clone()))
                    .await
                    .unwrap();
                (data.len() as i64, hash)
            }
            None => (size, synthetic_hash(hash_seed)),
        };
        let mut inode = Inode {
            id: None,
            parent_id,
            author_id: uid,
            name: name.to_string(),
            inode_type: INODE_FILE,
            size,
            ctime,
            mtime,
            mime_type: mime.to_string(),
            file_hash,
        };
        let id = space.add_inode(&inode).await.unwrap();
        inode.id = Some(id);
        model.record_seeded(&inode, TEST_USER_NAME, bytes);
        inode
    }

    async fn rename_recorded(space: &Space, model: &mut FsModel, inode_id: i64, new_name: &str) {
        let before = chrono::Utc::now().timestamp();
        let renamed = rename_inode(space, inode_id, new_name).await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(renamed, "rename_inode({inode_id}) should update one inode");
        model.rename(inode_id, new_name, TimeExpect::window(before, after));
    }

    async fn move_recorded(space: &Space, model: &mut FsModel, inode_id: i64, new_parent_id: i64) {
        let before = chrono::Utc::now().timestamp();
        let moved = move_inode(space, inode_id, new_parent_id).await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(moved, "move_inode({inode_id}) should update one inode");
        model.reparent(inode_id, new_parent_id, TimeExpect::window(before, after));
    }

    /// Stage T1 gate: upload a file via the `upload_files` wrapper, then assert
    /// the whole read surface agrees with the model — every `InodeWithAuthor`
    /// field exactly (with `ctime`/`mtime` inside the before/after window) and
    /// the bytes round-tripping through `download_file` /
    /// `download_file_by_hash`.
    #[tokio::test]
    async fn create_file_roundtrip() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let data = b"hello world".to_vec();

        let before = chrono::Utc::now().timestamp();
        let created = upload_files(
            &space,
            0,
            uid,
            vec![pending("notes.txt", "text/plain", &data)],
        )
        .await
        .unwrap();
        let after = chrono::Utc::now().timestamp();

        assert_eq!(created.len(), 1, "one file uploaded");
        let inode = &created[0];

        let mut model = FsModel::new();
        model.record_created(
            inode,
            CreateArgs {
                parent: 0,
                name: "notes.txt",
                author: uid,
                author_name: TEST_USER_NAME,
                inode_type: INODE_FILE,
                size: data.len() as i64,
                mime: "text/plain",
                file_hash: None,
                bytes: Some(data.clone()),
                ctime: TimeExpect::window(before, after),
                mtime: TimeExpect::window(before, after),
            },
        );

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn create_folder_roundtrip() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();

        create_folder_recorded(&space, &mut model, uid, 0, "projects").await;

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn list_children_field_coverage() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();

        let folder =
            seed_folder_recorded(&space, &mut model, uid, 0, "seeded-folder", 1_700, 1_711).await;
        seed_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&folder),
            "seeded-file.bin",
            "application/octet-stream",
            0,
            Some(vec![0, 1, 2, 3, 4, 255]),
            0xa1,
            1_720,
            1_721,
        )
        .await;

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn list_dir_orders_folders_first_then_ctime_desc() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();

        seed_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "new-file.txt",
            "text/plain",
            12,
            None,
            0xb1,
            300,
            300,
        )
        .await;
        seed_folder_recorded(&space, &mut model, uid, 0, "old-folder", 100, 100).await;
        seed_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "old-file.txt",
            "text/plain",
            8,
            None,
            0xb2,
            200,
            200,
        )
        .await;
        seed_folder_recorded(&space, &mut model, uid, 0, "new-folder", 400, 400).await;

        let listing = list_children(&space, 0).await.unwrap();
        let names: Vec<&str> = listing.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["new-folder", "old-folder", "new-file.txt", "old-file.txt"]
        );

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn rename_sets_name_and_mtime() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        let inode = upload_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "draft.txt",
            "text/plain",
            b"first draft",
        )
        .await;
        assert_matches_model(&space, &model).await;

        rename_recorded(&space, &mut model, inode_id(&inode), "final.txt").await;

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn move_reparents_and_sets_mtime() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        let old_parent = create_folder_recorded(&space, &mut model, uid, 0, "inbox").await;
        let new_parent = create_folder_recorded(&space, &mut model, uid, 0, "archive").await;
        let inode = upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&old_parent),
            "move-me.txt",
            "text/plain",
            b"move me",
        )
        .await;
        assert_matches_model(&space, &model).await;

        move_recorded(&space, &mut model, inode_id(&inode), inode_id(&new_parent)).await;

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn move_rejected_cases_error() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        let folder = create_folder_recorded(&space, &mut model, uid, 0, "folder").await;
        let file = upload_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "not-a-folder.txt",
            "text/plain",
            b"not a folder",
        )
        .await;
        assert_matches_model(&space, &model).await;

        let into_file = move_inode(&space, inode_id(&folder), inode_id(&file)).await;
        assert!(into_file.is_err(), "moving into a file must error");
        assert_matches_model(&space, &model).await;

        let to_self = move_inode(&space, inode_id(&folder), inode_id(&folder)).await;
        assert!(to_self.is_err(), "moving an inode to itself must error");
        assert_matches_model(&space, &model).await;

        let missing_parent = move_inode(&space, inode_id(&folder), 9_999_999).await;
        assert!(
            missing_parent.is_err(),
            "moving to a missing parent must error"
        );
        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn move_missing_target() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        create_folder_recorded(&space, &mut model, uid, 0, "survivor").await;
        assert_matches_model(&space, &model).await;

        let moved = move_inode(&space, 9_999_999, 0).await.unwrap();
        assert!(!moved, "missing move target is a no-op returning false");

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn create_into_bad_parent_errors() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        // A real file to use as an (invalid) parent, plus a baseline that must
        // stay unchanged through the rejected creates.
        let file = upload_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "real-file.txt",
            "text/plain",
            b"i am a file",
        )
        .await;
        assert_matches_model(&space, &model).await;

        // create_folder under a *file* → rejected by the add_inode parent assert.
        let under_file = create_folder(&space, inode_id(&file), uid, "nope").await;
        assert!(
            under_file.is_err(),
            "create_folder under a file must error: {under_file:?}"
        );
        // upload_files under a *file* → rejected. upload_files has its own
        // pre-upload path, so pin it independently of create_folder.
        let upload_under_file = upload_files(
            &space,
            inode_id(&file),
            uid,
            vec![pending("nope.txt", "text/plain", b"x")],
        )
        .await;
        assert!(
            upload_under_file.is_err(),
            "upload_files under a file must error: {upload_under_file:?}"
        );
        // upload_files under a *missing* parent → rejected.
        let upload_missing = upload_files(
            &space,
            9_999_999,
            uid,
            vec![pending("nope.txt", "text/plain", b"x")],
        )
        .await;
        assert!(
            upload_missing.is_err(),
            "upload_files under a missing parent must error: {upload_missing:?}"
        );
        // create_folder under a *missing* parent → rejected.
        let folder_missing = create_folder(&space, 9_999_999, uid, "nope").await;
        assert!(
            folder_missing.is_err(),
            "create_folder under a missing parent must error: {folder_missing:?}"
        );

        // None of the rejected creates touched the tree.
        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn upload_files_batch() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();

        let expected: [(&str, &str, &[u8]); 3] = [
            ("a.txt", "text/plain", b"alpha"),
            ("b.bin", "application/octet-stream", &[0, 1, 2]),
            ("c.md", "text/markdown", b"# gamma"),
        ];
        let batch: Vec<PendingFile> = expected
            .iter()
            .map(|(name, mime, data)| pending(name, mime, data))
            .collect();

        let before = chrono::Utc::now().timestamp();
        let created = upload_files(&space, 0, uid, batch).await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert_eq!(created.len(), 3, "three files uploaded in one call");

        for (inode, (name, mime, data)) in created.iter().zip(expected) {
            model.record_created(
                inode,
                CreateArgs {
                    parent: 0,
                    name,
                    author: uid,
                    author_name: TEST_USER_NAME,
                    inode_type: INODE_FILE,
                    size: data.len() as i64,
                    mime,
                    file_hash: None,
                    bytes: Some(data.to_vec()),
                    ctime: TimeExpect::window(before, after),
                    mtime: TimeExpect::window(before, after),
                },
            );
        }

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn rename_missing_target() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        create_folder_recorded(&space, &mut model, uid, 0, "survivor").await;
        assert_matches_model(&space, &model).await;

        let renamed = rename_inode(&space, 9_999_999, "ghost").await.unwrap();
        assert!(
            !renamed,
            "renaming a missing target is a no-op returning false"
        );

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn delete_missing_target() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        create_folder_recorded(&space, &mut model, uid, 0, "survivor").await;
        assert_matches_model(&space, &model).await;

        let deleted = delete_inode_recursive(&space, 9_999_999).await.unwrap();
        assert!(
            !deleted,
            "deleting a missing target is a no-op returning false"
        );

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn delete_recursive_removes_subtree() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        let keep = create_folder_recorded(&space, &mut model, uid, 0, "keep").await;
        upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&keep),
            "keep.txt",
            "text/plain",
            b"kept",
        )
        .await;
        let trash = create_folder_recorded(&space, &mut model, uid, 0, "trash").await;
        let nested =
            create_folder_recorded(&space, &mut model, uid, inode_id(&trash), "nested").await;
        upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&trash),
            "trash-root.txt",
            "text/plain",
            b"trash root",
        )
        .await;
        upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&nested),
            "trash-nested.txt",
            "text/plain",
            b"trash nested",
        )
        .await;
        assert_matches_model(&space, &model).await;

        let deleted = delete_inode_recursive(&space, inode_id(&trash))
            .await
            .unwrap();
        assert!(
            deleted,
            "delete_inode_recursive should delete the root inode"
        );
        model.delete_recursive(inode_id(&trash));

        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn upload_download_bytes_roundtrip() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();
        let data = vec![0, 1, 2, 3, 128, 255, 42, 7, 9, 11];

        let inode = upload_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "bytes.bin",
            "application/octet-stream",
            &data,
        )
        .await;
        let hash = inode.file_hash.hash().unwrap().to_string();

        assert_eq!(download_file(&space, inode_id(&inode)).await.unwrap(), data);
        assert_eq!(download_file_by_hash(&space, &hash).await.unwrap(), data);
        assert_matches_model(&space, &model).await;
    }

    #[tokio::test]
    async fn deep_tree_consistency() {
        let space = create_test_space().await;
        let uid = space.get_auth_context().uid.unwrap();
        let mut model = FsModel::new();

        let docs = create_folder_recorded(&space, &mut model, uid, 0, "docs").await;
        assert_matches_model(&space, &model).await;
        let archive = create_folder_recorded(&space, &mut model, uid, 0, "archive").await;
        assert_matches_model(&space, &model).await;
        upload_file_recorded(
            &space,
            &mut model,
            uid,
            0,
            "root.txt",
            "text/plain",
            b"root",
        )
        .await;
        assert_matches_model(&space, &model).await;
        let plan = upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&docs),
            "plan.md",
            "text/markdown",
            b"plan",
        )
        .await;
        assert_matches_model(&space, &model).await;
        let drafts =
            create_folder_recorded(&space, &mut model, uid, inode_id(&docs), "drafts").await;
        assert_matches_model(&space, &model).await;
        let draft = upload_file_recorded(
            &space,
            &mut model,
            uid,
            inode_id(&drafts),
            "v1.md",
            "text/markdown",
            b"v1",
        )
        .await;
        assert_matches_model(&space, &model).await;

        rename_recorded(&space, &mut model, inode_id(&plan), "plan-final.md").await;
        assert_matches_model(&space, &model).await;
        move_recorded(&space, &mut model, inode_id(&drafts), inode_id(&archive)).await;
        assert_matches_model(&space, &model).await;
        rename_recorded(&space, &mut model, inode_id(&draft), "v2.md").await;
        assert_matches_model(&space, &model).await;

        let deleted = delete_inode_recursive(&space, inode_id(&archive))
            .await
            .unwrap();
        assert!(deleted, "delete_inode_recursive should delete archive");
        model.delete_recursive(inode_id(&archive));
        assert_matches_model(&space, &model).await;
    }

    #[derive(Debug, Clone, Copy)]
    struct LocalNode {
        parent: i64,
        inode_type: i64,
    }

    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn usize(&mut self, upper: usize) -> usize {
            assert!(upper > 0, "upper bound must be nonzero");
            (self.next() as usize) % upper
        }
    }

    fn folder_ids(live: &BTreeMap<i64, LocalNode>) -> Vec<i64> {
        let mut ids = vec![0];
        ids.extend(
            live.iter()
                .filter(|(_, node)| node.inode_type == INODE_FOLDER)
                .map(|(id, _)| *id),
        );
        ids
    }

    fn is_descendant(
        live: &BTreeMap<i64, LocalNode>,
        possible_descendant: i64,
        ancestor: i64,
    ) -> bool {
        let mut cur = possible_descendant;
        while cur != 0 {
            if cur == ancestor {
                return true;
            }
            let Some(node) = live.get(&cur) else {
                return false;
            };
            cur = node.parent;
        }
        false
    }

    fn valid_move_pairs(live: &BTreeMap<i64, LocalNode>) -> Vec<(i64, i64)> {
        let folders = folder_ids(live);
        let mut pairs = Vec::new();
        for (id, node) in live {
            for parent in &folders {
                if *parent == node.parent || *parent == *id {
                    continue;
                }
                if node.inode_type == INODE_FOLDER && is_descendant(live, *parent, *id) {
                    continue;
                }
                pairs.push((*id, *parent));
            }
        }
        pairs
    }

    fn remove_local_subtree(live: &mut BTreeMap<i64, LocalNode>, id: i64) {
        let mut subtree = vec![id];
        let mut cursor = 0;
        while cursor < subtree.len() {
            let cur = subtree[cursor];
            let children: Vec<i64> = live
                .iter()
                .filter(|(_, node)| node.parent == cur)
                .map(|(child, _)| *child)
                .collect();
            subtree.extend(children);
            cursor += 1;
        }
        for removed in subtree {
            live.remove(&removed);
        }
    }

    #[tokio::test]
    async fn randomized_consistency() {
        for case in 0..3 {
            let space = create_test_space().await;
            let uid = space.get_auth_context().uid.unwrap();
            let mut model = FsModel::new();
            let mut live = BTreeMap::new();
            let mut rng = TestRng::new(0xf51e_0000 + case);

            for step in 0..18 {
                let roll = rng.usize(100);
                if live.is_empty() || roll < 25 {
                    let parents = folder_ids(&live);
                    let parent = parents[rng.usize(parents.len())];
                    let inode = create_folder_recorded(
                        &space,
                        &mut model,
                        uid,
                        parent,
                        &format!("folder-{case}-{step}"),
                    )
                    .await;
                    live.insert(
                        inode_id(&inode),
                        LocalNode {
                            parent,
                            inode_type: INODE_FOLDER,
                        },
                    );
                } else if roll < 50 {
                    let parents = folder_ids(&live);
                    let parent = parents[rng.usize(parents.len())];
                    let data = format!("file-bytes-{case}-{step}-{}", rng.next()).into_bytes();
                    let inode = upload_file_recorded(
                        &space,
                        &mut model,
                        uid,
                        parent,
                        &format!("file-{case}-{step}.txt"),
                        "text/plain",
                        &data,
                    )
                    .await;
                    live.insert(
                        inode_id(&inode),
                        LocalNode {
                            parent,
                            inode_type: INODE_FILE,
                        },
                    );
                } else if roll < 65 {
                    let ids: Vec<i64> = live.keys().copied().collect();
                    let target = ids[rng.usize(ids.len())];
                    rename_recorded(
                        &space,
                        &mut model,
                        target,
                        &format!("renamed-{case}-{step}"),
                    )
                    .await;
                } else if roll < 82 {
                    let pairs = valid_move_pairs(&live);
                    if pairs.is_empty() {
                        let inode = create_folder_recorded(
                            &space,
                            &mut model,
                            uid,
                            0,
                            &format!("fallback-folder-{case}-{step}"),
                        )
                        .await;
                        live.insert(
                            inode_id(&inode),
                            LocalNode {
                                parent: 0,
                                inode_type: INODE_FOLDER,
                            },
                        );
                    } else {
                        let (target, parent) = pairs[rng.usize(pairs.len())];
                        move_recorded(&space, &mut model, target, parent).await;
                        live.get_mut(&target).unwrap().parent = parent;
                    }
                } else {
                    let ids: Vec<i64> = live.keys().copied().collect();
                    let target = ids[rng.usize(ids.len())];
                    let deleted = delete_inode_recursive(&space, target).await.unwrap();
                    assert!(deleted, "delete_inode_recursive({target}) should delete");
                    model.delete_recursive(target);
                    remove_local_subtree(&mut live, target);
                }

                assert_matches_model(&space, &model).await;
            }
        }
    }
}
