use anyhow::Result;
use encrypted_spaces_sdk::PieceTextArea;

pub async fn get_notes_text(doc: &PieceTextArea) -> Result<String> {
    log::debug!("[notes] get_notes_text: syncing...");
    doc.sync().await?;
    let text = doc.snapshot().await?;
    log::debug!(
        "[notes] get_notes_text: len={} text={:?}",
        text.len(),
        // char-safe preview: byte slicing would panic if the cutoff split a
        // multi-byte scalar (normal emoji/non-ASCII notes).
        text.chars().take(80).collect::<String>()
    );
    Ok(text)
}

pub async fn notes_insert(doc: &PieceTextArea, pos: usize, text: &str) -> Result<()> {
    let len = doc.len().await?;
    log::debug!(
        "[notes] notes_insert: pos={} text={:?} doc_len={}",
        pos,
        // char-safe preview: byte slicing would panic mid-scalar on non-ASCII.
        text.chars().take(40).collect::<String>(),
        len
    );
    if pos == len {
        doc.append_string(text).await?;
    } else {
        doc.insert_string(pos, text).await?;
    }
    log::debug!("[notes] notes_insert: done, new_len={}", doc.len().await?);
    Ok(())
}

pub async fn notes_delete(doc: &PieceTextArea, pos: usize, count: usize) -> Result<()> {
    log::debug!(
        "[notes] notes_delete: pos={} count={} doc_len={}",
        pos,
        count,
        doc.len().await?
    );
    let end = pos.checked_add(count).ok_or_else(|| {
        anyhow::anyhow!("notes_delete: pos {pos} + count {count} overflows usize")
    })?;
    doc.delete_range(pos, end).await?;
    log::debug!("[notes] notes_delete: done, new_len={}", doc.len().await?);
    Ok(())
}

/// Convert a UTF-16 code-unit offset — how the JS/TypeScript frontend counts
/// document positions (`String.length`, `selectionStart`) — into a Unicode
/// scalar (char) offset, which is what the scalar-indexed notes API expects.
///
/// Astral characters (e.g. emoji) are a single scalar but two UTF-16 code
/// units, so the two coordinate systems diverge after the first astral
/// character. The offset is clamped to the document length; an offset landing
/// inside a surrogate pair rounds up to the next scalar boundary.
pub fn utf16_offset_to_scalar(text: &str, utf16_offset: usize) -> usize {
    let mut units = 0usize;
    for (scalar_idx, ch) in text.chars().enumerate() {
        if units >= utf16_offset {
            return scalar_idx;
        }
        units += ch.len_utf16();
    }
    text.chars().count()
}

async fn notes_baseline_text(doc: &PieceTextArea) -> Result<String> {
    if let Some(text) = doc.snapshot_from_cached_render().await? {
        return Ok(text);
    }
    get_notes_text(doc).await
}

/// Apply a frontend diff whose position and deleted length are UTF-16 code
/// units. If the document is already rendered locally, the offsets are resolved
/// against that cached baseline instead of first syncing remote changes; this
/// preserves the user's visible edit anchors across concurrent remote edits.
pub async fn notes_apply_diff_utf16(
    doc: &PieceTextArea,
    utf16_pos: usize,
    utf16_delete_count: usize,
    inserted: &str,
) -> Result<()> {
    if utf16_delete_count == 0 && inserted.is_empty() {
        return Ok(());
    }

    let baseline = notes_baseline_text(doc).await?;
    let scalar_start = utf16_offset_to_scalar(&baseline, utf16_pos);
    let utf16_end = utf16_pos.checked_add(utf16_delete_count).ok_or_else(|| {
        anyhow::anyhow!(
            "notes_apply_diff_utf16: utf16_pos {utf16_pos} + utf16_delete_count \
             {utf16_delete_count} overflows usize"
        )
    })?;
    let scalar_end = utf16_offset_to_scalar(&baseline, utf16_end);
    doc.apply_diff_from_cached_snapshot(scalar_start, scalar_end - scalar_start, inserted)
        .await?;
    Ok(())
}

/// `notes_insert` whose `utf16_pos` is a UTF-16 code-unit offset from the
/// frontend.
pub async fn notes_insert_utf16(doc: &PieceTextArea, utf16_pos: usize, text: &str) -> Result<()> {
    notes_apply_diff_utf16(doc, utf16_pos, 0, text).await
}

/// `notes_delete` whose `utf16_pos`/`utf16_count` are UTF-16 code-unit values
/// from the frontend.
pub async fn notes_delete_utf16(
    doc: &PieceTextArea,
    utf16_pos: usize,
    utf16_count: usize,
) -> Result<()> {
    notes_apply_diff_utf16(doc, utf16_pos, utf16_count, "").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_sdk::{
        local_transport::LocalTransport,
        schema::{ApplicationSchema, ColumnType, SchemaBuilder},
        PieceCoordList, PieceTextArea, Space,
    };
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    const TABLE: &str = "test_table";
    const COL: &str = "notes";
    const TEST_SCHEMA_BYTES: &[u8] = include_bytes!("../../app_schema.kdl");

    #[derive(Debug, Serialize, Deserialize)]
    struct Row {
        id: Option<i64>,
        name: String,
        notes: PieceCoordList,
    }

    async fn create_piece_text_area() -> anyhow::Result<PieceTextArea> {
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::PieceText)?
            .build()?;
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, None).await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;
        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                notes: PieceCoordList::empty(),
            })
            .execute()
            .await?;
        Ok(space.piece_text(TABLE, row_id, COL))
    }

    async fn create_demo_space_pair() -> anyhow::Result<(Space, Space)> {
        let text = std::str::from_utf8(TEST_SCHEMA_BYTES)?;
        let bundle = encrypted_spaces_sdk::testing::parse_schema_bundle(text)?;
        let schemas: Vec<encrypted_spaces_sdk::Schema> = bundle
            .tables
            .iter()
            .filter_map(|t| t.schema.clone())
            .collect();

        std::env::set_var("RISC0_DEV_MODE", "1");
        let transport = LocalTransport::new(&schemas, None, Some(10_000)).await?;
        transport
            .import_actions(&bundle.actions, &bundle.acl_only_via_actions)
            .await?;
        let commitment = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing_from_bytes(TEST_SCHEMA_BYTES, commitment);

        let alice = Space::create(transport.clone(), app_schema.clone()).await?;
        let alice_uid = alice.uid().expect("alice has a uid") as i64;
        crate::chat::set_user_name(&alice, alice_uid, "alice").await?;

        let invite = alice.invite_user().await?;
        let bob = Space::join(transport, invite, app_schema).await?;
        let bob_uid = bob.uid().expect("bob has a uid") as i64;
        crate::chat::set_user_name(&bob, bob_uid, "bob").await?;

        alice.sync().await?;
        bob.sync().await?;
        Ok((alice, bob))
    }

    async fn create_demo_state_for_channel(
        space: &Space,
        channel_id: i64,
        channel_name: &str,
    ) -> crate::state::AppState {
        use crate::state::{AppState, UserInfo};

        let state = AppState::new(100, None);
        *state.space.lock().await = Some(Arc::new(space.clone()));
        *state.user_info.lock().await = Some(UserInfo {
            user_id: space.uid().expect("space has a uid") as i64,
            user_name: "test-user".to_string(),
            ws_address: String::new(),
            current_channel_id: channel_id,
            current_channel_name: channel_name.to_string(),
        });
        *state.notes.lock().await = Some(space.piece_text("channels", channel_id, "notes"));
        state
    }

    #[tokio::test]
    async fn test_empty_notes() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_and_snapshot() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        notes_insert(&doc, 0, "Hello").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_append_via_insert_at_end() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        notes_insert(&doc, 0, "Hello").await?;
        notes_insert(&doc, 5, " World").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello World");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_middle() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        notes_insert(&doc, 0, "Hllo").await?;
        notes_insert(&doc, 1, "e").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_delete() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        notes_insert(&doc, 0, "Hello World").await?;
        notes_delete(&doc, 5, 6).await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_then_delete_then_insert() -> anyhow::Result<()> {
        let doc = create_piece_text_area().await?;
        notes_insert(&doc, 0, "abc").await?;
        notes_delete(&doc, 1, 1).await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "ac");
        notes_insert(&doc, 1, "B").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "aBc");
        Ok(())
    }

    #[test]
    fn utf16_offset_to_scalar_handles_astral() {
        // "a😀b": 'a'=1 unit, '😀'=2 units, 'b'=1 unit → 4 UTF-16 units, 3 scalars.
        let s = "a😀b";
        assert_eq!(utf16_offset_to_scalar(s, 0), 0); // before 'a'
        assert_eq!(utf16_offset_to_scalar(s, 1), 1); // before the emoji
        assert_eq!(utf16_offset_to_scalar(s, 3), 2); // after the emoji, before 'b'
        assert_eq!(utf16_offset_to_scalar(s, 4), 3); // end of document
        assert_eq!(utf16_offset_to_scalar(s, 99), 3); // clamps to length
                                                      // Offset 2 sits between the emoji's surrogates; it rounds up to the next
                                                      // scalar boundary, which is after the emoji (scalar 2).
        assert_eq!(utf16_offset_to_scalar(s, 2), 2);
        // Pure-ASCII text: UTF-16 offsets equal scalar offsets.
        assert_eq!(utf16_offset_to_scalar("hello", 3), 3);
    }

    #[tokio::test]
    async fn test_astral_position_round_trip_through_command_path() -> anyhow::Result<()> {
        let (space, _bob) = create_demo_space_pair().await?;
        let channel_id = crate::chat::get_or_create_channel(&space, "general").await?;
        let doc = space.piece_text("channels", channel_id, "notes");
        let state = create_demo_state_for_channel(&space, channel_id, "general").await;

        // Drive the real Tauri command bodies (minus the `State` newtype) so the
        // UTF-16 → scalar conversion runs exactly as the frontend reaches it.
        // The frontend works in UTF-16 code units; the notes API is scalar-indexed.
        crate::commands::notes_insert_impl(&state, channel_id, 0, "a😀b")
            .await
            .unwrap();
        assert_eq!(get_notes_text(&doc).await?, "a😀b");
        // Cursor after the emoji is UTF-16 offset 3 (a=1, emoji=2). Treating that
        // offset as a scalar index would land inside the emoji; the conversion
        // maps it to scalar 2, before 'b'.
        crate::commands::notes_insert_impl(&state, channel_id, 3, "X")
            .await
            .unwrap();
        assert_eq!(get_notes_text(&doc).await?, "a😀Xb");
        // Delete the emoji: it spans UTF-16 offset 1 for 2 code units.
        crate::commands::notes_delete_impl(&state, channel_id, 1, 2)
            .await
            .unwrap();
        assert_eq!(get_notes_text(&doc).await?, "aXb");
        Ok(())
    }

    #[tokio::test]
    async fn test_apply_diff_command_replaces_utf16_range() -> anyhow::Result<()> {
        let (space, _bob) = create_demo_space_pair().await?;
        let channel_id = crate::chat::get_or_create_channel(&space, "general").await?;
        let doc = space.piece_text("channels", channel_id, "notes");
        let state = create_demo_state_for_channel(&space, channel_id, "general").await;

        crate::commands::notes_apply_diff_impl(&state, channel_id, 0, 0, "a😀b")
            .await
            .unwrap();
        assert_eq!(get_notes_text(&doc).await?, "a😀b");

        crate::commands::notes_apply_diff_impl(&state, channel_id, 1, 2, "ZZ")
            .await
            .unwrap();
        assert_eq!(get_notes_text(&doc).await?, "aZZb");
        Ok(())
    }

    #[tokio::test]
    async fn stale_utf16_offset_after_remote_insert_preserves_visible_anchor() -> anyhow::Result<()>
    {
        let (alice, bob) = create_demo_space_pair().await?;
        let channel_id = crate::chat::get_or_create_channel(&alice, "general").await?;
        bob.sync().await?;

        let alice_notes = alice.piece_text("channels", channel_id, "notes");
        let bob_notes = bob.piece_text("channels", channel_id, "notes");
        let state = create_demo_state_for_channel(&bob, channel_id, "general").await;

        notes_insert(&alice_notes, 0, "abc").await?;
        bob_notes.sync().await?;
        assert_eq!(get_notes_text(&bob_notes).await?, "abc");

        // Bob's UI cursor is still at UTF-16 offset 3 in the stale "abc"
        // snapshot. Alice inserts at the front before Bob's pending flush
        // reaches the command path.
        notes_insert(&alice_notes, 0, "Q").await?;
        crate::commands::notes_insert_impl(&state, channel_id, 3, "X")
            .await
            .unwrap();

        alice_notes.sync().await?;
        bob_notes.sync().await?;
        let alice_snapshot = get_notes_text(&alice_notes).await?;
        let bob_snapshot = get_notes_text(&bob_notes).await?;
        assert_eq!(alice_snapshot, bob_snapshot);
        assert_eq!(
            bob_snapshot, "QabcX",
            "a raw stale offset is currently applied against the post-sync text"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_notes_flush_after_channel_switch_targets_original_channel(
    ) -> anyhow::Result<()> {
        let (space, _bob) = create_demo_space_pair().await?;
        let alpha_id = crate::chat::get_or_create_channel(&space, "alpha").await?;
        let beta_id = crate::chat::get_or_create_channel(&space, "beta").await?;
        let alpha_notes = space.piece_text("channels", alpha_id, "notes");
        let beta_notes = space.piece_text("channels", beta_id, "notes");

        let state = create_demo_state_for_channel(&space, alpha_id, "alpha").await;

        // This simulates a debounced frontend write that was prepared while
        // editing alpha, but reaches the command after the app has switched the
        // ambient notes handle to beta.
        *state.notes.lock().await = Some(space.piece_text("channels", beta_id, "notes"));
        crate::commands::notes_insert_impl(&state, alpha_id, 0, "pending-alpha")
            .await
            .unwrap();

        let alpha_snapshot = get_notes_text(&alpha_notes).await?;
        let beta_snapshot = get_notes_text(&beta_notes).await?;
        assert_eq!(
            alpha_snapshot, "pending-alpha",
            "pending write should stay on alpha; alpha={alpha_snapshot:?} beta={beta_snapshot:?}"
        );
        assert_eq!(
            beta_snapshot, "",
            "pending alpha write must not land on the newly selected channel"
        );
        Ok(())
    }
}
