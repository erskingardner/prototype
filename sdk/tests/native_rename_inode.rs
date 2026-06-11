//! End-to-end: native `rename_inode` is accepted, applied, and proven through
//! the FF pipeline on MRT.
//!
//! This drives the full client→server→client native path: the SDK builds the
//! two-kv `OpType::Native` envelope (encoders), the server accepts it (envelope
//! shape, strict freshness, missing-target probe, native-aware hash sidecar),
//! the host applies the verifier's `write_steps` through the MRT trace
//! materializer (`apply_change_with_pruned_tree*`), and the client re-runs E&V
//! and verifies the returned trace witness against the new root. Because the
//! native op flows through the *same* extract-and-validate + trace machinery as
//! data-driven ops, its `write_steps` derivation is proven automatically — no
//! native-specific proving code.

#![cfg(feature = "local-transport")]

use encrypted_spaces_sdk::transport::Transport;
use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, QueryParam, Space};
use serde_json::Value;

type TestResult<T> = encrypted_spaces_sdk::SdkResult<T>;

const RENAME_INODE_SCHEMA_BYTES: &[u8] = include_bytes!("fixtures/native_rename_inode.kdl");
const RENAME_INODE_SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/native_rename_inode.kdl"
);

/// A space whose `inodes` table mirrors `app_schema.kdl`, trimmed to the columns
/// native `rename_inode` touches. The `add_inode` / `move_inode` /
/// `rename_inode` actions + `only_via_actions` gate keep the data-driven path a
/// valid writer (coexistence) while raw CRUD on `inodes` is blocked.
async fn fresh_rename_inode_space() -> TestResult<(LocalTransport, Space, ApplicationSchema)> {
    let transport = LocalTransport::from_schema_file(RENAME_INODE_SCHEMA_PATH).await?;
    let root = transport.get_root_hash().await?;
    let app_schema = ApplicationSchema::for_testing_from_bytes(RENAME_INODE_SCHEMA_BYTES, root);
    let space = Space::create(transport.clone(), app_schema.clone()).await?;
    Ok((transport, space, app_schema))
}

/// Seed a root file inode via the data-driven `add_inode` action so its `name`
/// (hash-backed) and `mtime` (encrypted) columns are on the normal write path.
async fn insert_inode(
    space: &Space,
    author_id: i64,
    name: &str,
    inode_type: i64,
    mtime: i64,
) -> TestResult<i64> {
    space
        .call_insert_action(
            "add_inode",
            vec![
                ("parent_id".to_string(), QueryParam::Integer(0)),
                ("author_id".to_string(), QueryParam::Integer(author_id)),
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("type".to_string(), QueryParam::Integer(inode_type)),
                ("mtime".to_string(), QueryParam::Integer(mtime)),
            ],
        )
        .await
}

/// Read back the decrypted `name` + `mtime` of one inode — the proof both
/// columns moved together and that the verbatim `mtime` ciphertext decrypts
/// cleanly.
async fn inode_name_mtime(space: &Space, inode_id: i64) -> TestResult<(String, i64)> {
    let row = space
        .table::<Value>("inodes")
        .select()
        .where_eq("id", inode_id)
        .first()
        .await?
        .expect("inode row exists");
    Ok((
        row.get("name")
            .and_then(Value::as_str)
            .expect("name is text")
            .to_string(),
        row.get("mtime")
            .and_then(Value::as_i64)
            .expect("mtime is int"),
    ))
}

#[tokio::test]
async fn native_rename_inode_accepts_applies_and_noops() -> TestResult<()> {
    let (transport, alice, _schema) = fresh_rename_inode_space().await?;
    let alice_uid = alice.uid().expect("alice uid") as i64;

    // Seed a root file inode on the data-driven path.
    let inode_id = insert_inode(&alice, alice_uid, "original.txt", 1, 1000).await?;
    assert_eq!(
        inode_name_mtime(&alice, inode_id).await?,
        ("original.txt".to_string(), 1000)
    );

    // ── Accept: existing inode → rows == 1, both columns move together ──────
    // `mtime` decrypting cleanly on read-back is the proof the verbatim-bytes
    // write is correct; both columns moved together (rename atomicity).
    let rows = alice
        .submit_rename_inode_native(inode_id, "renamed.txt", 2000)
        .await?;
    assert_eq!(rows, 1);
    assert_eq!(
        inode_name_mtime(&alice, inode_id).await?,
        ("renamed.txt".to_string(), 2000)
    );

    // ── No-op: non-existent inode → rows == 0, no error, no new change ──────
    let before_noop = alice.current_change_id();
    let rows = alice
        .submit_rename_inode_native(9_999_999, "nope", 3000)
        .await?;
    assert_eq!(rows, 0, "missing inode is a graceful no-op");
    assert_eq!(
        alice.current_change_id(),
        before_noop,
        "a no-op native op appends no changelog entry"
    );
    let no_new_changes = transport.fast_forward(before_noop).await?;
    assert!(no_new_changes.changes.is_empty());
    assert!(no_new_changes.responses.is_empty());

    Ok(())
}

/// Drives the actual FF STARK over native `rename_inode`: submit enough native
/// renames to cross a batch boundary so the server proves a range that contains
/// native write_steps, then fast-forward a remote reader THROUGH that proof.
/// Because native ops ride the same extract-and-validate + trace pipeline as
/// data-driven ops, the FF prover covers their write_steps with no
/// native-specific proving code — this test confirms that end to end.
///
/// Skipped when `RISC0_SKIP_BUILD` is set (no guest → no proving), matching the
/// other FF-proof integration tests; run under `RISC0_DEV_MODE=1`.
#[tokio::test]
async fn native_rename_inode_proven_in_ff_batch() -> TestResult<()> {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping native_rename_inode_proven_in_ff_batch: RISC0_SKIP_BUILD is set");
        return Ok(());
    }

    let (transport, alice, _schema) = fresh_rename_inode_space().await?;
    let alice_uid = alice.uid().expect("alice uid") as i64;

    // A remote reader snapshotted before the renames must catch up THROUGH the
    // FF proof the server generates at the batch boundary.
    let snapshot = alice.snapshot().await?;
    let remote = Space::restore(transport.clone(), snapshot).await?;
    let remote_start = remote.current_change_id();

    // Seed an inode, then submit enough native renames to cross the FF batch
    // boundary (DEFAULT_FF_BATCH_SIZE = 5) so the proven range contains native
    // rename_inode write_steps.
    let inode_id = insert_inode(&alice, alice_uid, "v0.txt", 1, 1000).await?;
    for i in 1..=6_i64 {
        let rows = alice
            .submit_rename_inode_native(inode_id, &format!("v{i}.txt"), 1000 + i)
            .await?;
        assert_eq!(rows, 1, "each native rename hits the existing inode");
    }

    // The remote fast-forwards through the generated FF STARK proof, then drains
    // any ragged (post-proof) native renames to reach alice's head.
    let ff_data = transport.fast_forward(remote_start).await?;
    assert!(
        ff_data.proof.is_some(),
        "crossing the batch boundary must yield an FF proof covering native renames"
    );
    remote.apply_fast_forward(ff_data).await?;
    remote.sync().await?;

    assert_eq!(
        remote.current_data_commitment(),
        alice.current_data_commitment(),
        "remote reconstructs alice's state via the proof + ragged native renames"
    );
    assert_eq!(
        inode_name_mtime(&remote, inode_id).await?,
        ("v6.txt".to_string(), 1006)
    );

    Ok(())
}
