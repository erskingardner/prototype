//! Two-actor cold-read fixture for the self-consistent filesystem tests.
//!
//! Layer 3 of `docs/native_ops_plans/PLAN_FS_TEST.md`: actor A writes via the
//! demo's `files` verbs; after a sync, actor B's cache is cold for A's writes,
//! so reading through B exercises the committed / KV path the cache-bypassing
//! read ops will use — not A's warm cache. The single-space tests cover the
//! warm-cache path; pairing each with [`assert_cold_read`] checks the
//! interaction at both layers.

use anyhow::Result;

use crate::World;

// Re-export the shared model + checker so a cold-read test can pull the
// fixture and the assertions from one place. The `Tree*` items mirror the
// table model for the relative-inode tree backend (Stage T3), so the Stage T4
// harness can drive both id models through one set of scenario bodies.
pub use encrypted_spaces_demo::fs_test_model::{
    assert_matches_model, assert_tree_matches_model, CreateArgs, FsModel, Node, TimeExpect,
    TreeCreateArgs, TreeFsModel, TreeNode, FOLDER_HASH_HEX,
};

/// Build a [`World`] with two joined actors sharing one transport: `writer` as
/// the founder and `reader` invited and joined into `channel`. The caller
/// drives `files` writes as `writer`, then [`assert_cold_read`] checks the read
/// surface `reader` sees at the committed layer.
pub async fn two_actor_world(writer: &str, reader: &str, channel: &str) -> Result<World> {
    let mut world = World::new().await?;
    world.create_founder(writer, channel).await?;
    world.invite(writer, reader).await?;
    world.join(reader, channel).await?;
    // `reader`'s join (and its channel bootstrap) advanced the changelog past
    // `writer`'s local view; converge everyone so the caller's first write
    // commits on a current base rather than hitting "fast forward required".
    world.sync_all().await?;
    Ok(world)
}

/// Sync every actor (fast-forwarding `reader` past `writer`'s committed
/// changes), drop `reader`'s query cache, then assert the `files` read surface
/// seen by `reader` agrees with `model` — at the committed / KV layer.
///
/// The explicit `clear_query_cache` is load-bearing: fast-forward *repopulates*
/// the SDK cache (so id lookups like `download_file` would be served warm), and
/// a no-op sync leaves a previously-warmed cache in place (so `list_children`
/// could hit a bucket an earlier read marked complete). Clearing after the sync
/// forces every read in `assert_matches_model` through the backend, which is the
/// path the cache-bypassing read ops will use.
pub async fn assert_cold_read(world: &World, reader: &str, model: &FsModel) -> Result<()> {
    world.sync_all().await?;
    // `&Arc<Space>` coerces to `&Space` (same pattern the harness uses for
    // `files::list_children(&actor.space, ..)`).
    let reader_space = &world.actor(reader)?.space;
    reader_space.clear_query_cache();
    assert_matches_model(reader_space, model).await;
    Ok(())
}

/// Tree-backend counterpart of [`assert_cold_read`]: sync everyone,
/// fast-forwarding `reader` past the writer's committed tree-FS changes, drop
/// `reader`'s query cache, then assert the `files_tree` read surface seen by
/// `reader` agrees with the handle-keyed [`TreeFsModel`] at the committed / KV
/// layer.
///
/// Clearing the cache is load-bearing for the same reason it is in
/// [`assert_cold_read`]: the tree author-name join (`users_meta`) is served
/// from the SDK query cache, and the node reads go through the raw changelog at
/// `reader`'s current data commitment — both must reflect the just-synced
/// committed state, not a warm cache populated by the fast-forward.
pub async fn assert_tree_cold_read(world: &World, reader: &str, model: &TreeFsModel) -> Result<()> {
    world.sync_all().await?;
    let reader_space = &world.actor(reader)?.space;
    reader_space.clear_query_cache();
    assert_tree_matches_model(reader_space, model).await;
    Ok(())
}
