#![cfg(feature = "local-transport")]

mod piece_text_support;

use encrypted_spaces_backend::error::Result;
use encrypted_spaces_changelog_core::piece_text::{BufferCoord, PieceTextEditEnvelopeV1};
use piece_text_support::{create_two_client_piece_text_fixture, server_changelog_len, COL, TABLE};

async fn accepted_piece_text_count_since(
    transport: &encrypted_spaces_sdk::local_transport::LocalTransport,
    start: usize,
) -> usize {
    let state = transport.state_for_tests().await;
    state.changelog.changes[start..]
        .iter()
        .filter(|change| PieceTextEditEnvelopeV1::decode_from_entry(change).is_ok())
        .count()
}

async fn assert_same_snapshot(
    left: &encrypted_spaces_sdk::PieceTextArea,
    right: &encrypted_spaces_sdk::PieceTextArea,
    expected: &str,
) -> Result<()> {
    left.sync().await?;
    right.sync().await?;
    let left_snapshot = left.snapshot().await?;
    let right_snapshot = right.snapshot().await?;
    assert_eq!(left_snapshot, right_snapshot);
    assert_eq!(left_snapshot, expected);
    Ok(())
}

#[tokio::test]
async fn two_clients_concurrent_inserts_at_document_start_render_lifo() -> Result<()> {
    let fixture = create_two_client_piece_text_fixture().await?;
    let alice_area = fixture.alice.piece_text(TABLE, fixture.row_id, COL);
    let bob_area = fixture.bob.piece_text(TABLE, fixture.row_id, COL);

    let baseline = server_changelog_len(&fixture.transport).await;
    assert_same_snapshot(&alice_area, &bob_area, "").await?;

    alice_area
        .insert_at_coord(BufferCoord::DOCUMENT_START, "AAA")
        .await?;
    assert_same_snapshot(&alice_area, &bob_area, "AAA").await?;

    bob_area
        .insert_at_coord(BufferCoord::DOCUMENT_START, "BBB")
        .await?;
    assert_same_snapshot(&alice_area, &bob_area, "BBBAAA").await?;

    assert_eq!(
        accepted_piece_text_count_since(&fixture.transport, baseline).await,
        2,
        "accepted piece-text changelog entries must match the two submitted edits",
    );
    Ok(())
}
