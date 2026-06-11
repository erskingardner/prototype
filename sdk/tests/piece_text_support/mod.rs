#![cfg(feature = "local-transport")]

use encrypted_spaces_backend::{
    access_control::AuthContext,
    error::Result,
    internal_schemas::all_internal_schemas,
    query::{Query, QueryOperation, QueryParam},
    storage::Storage as _,
};
use encrypted_spaces_backend_server::SpaceState;
use encrypted_spaces_sdk::{
    local_transport::LocalTransport,
    schema::{ApplicationSchema, ColumnType, Schema, SchemaBuilder},
    Space,
};

pub const TABLE: &str = "channels";
pub const COL: &str = "notes_pieces";
pub const ROW_ID: i64 = 1;
pub const LIST_NUMBER: i64 = 1;

pub struct TwoClientFixture {
    pub transport: LocalTransport,
    pub alice: Space,
    pub bob: Space,
    pub row_id: i64,
}

pub fn parent_schema() -> Result<Schema> {
    SchemaBuilder::new(TABLE)
        .explicit_ids()
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)?
        .plaintext()
        .column(COL, ColumnType::PieceText)?
        .build()
}

pub async fn create_two_client_piece_text_fixture() -> Result<TwoClientFixture> {
    let parent = parent_schema()?;
    let mut schemas = all_internal_schemas();
    schemas.push(parent.clone());

    let transport =
        LocalTransport::new(&schemas, None, Some(SpaceState::DEFAULT_FF_BATCH_SIZE)).await?;
    let root = transport.get_root_hash().await?;
    let app_schema = ApplicationSchema::WithDataCommitment(
        vec![parent],
        root,
        encrypted_spaces_ffproof::EXTEND_FF_ID,
    );

    let alice = Space::create(transport.clone(), app_schema.clone()).await?;
    seed_parent_row(&transport, alice.id()).await?;
    alice
        .init_piece_text_address(TABLE, ROW_ID, COL, LIST_NUMBER)
        .await?;

    let invite = alice.invite_user().await?;
    let bob = Space::join(transport.clone(), invite, app_schema).await?;

    alice.sync().await?;
    bob.sync().await?;

    Ok(TwoClientFixture {
        transport,
        alice,
        bob,
        row_id: ROW_ID,
    })
}

async fn seed_parent_row(
    transport: &LocalTransport,
    space_id: encrypted_spaces_backend::SpaceId,
) -> Result<()> {
    let state = transport.state_for_tests().await;
    state
        .db
        .insert(
            Query::new(
                TABLE.to_string(),
                QueryOperation::Insert(vec![
                    ("id".to_string(), QueryParam::Integer(ROW_ID)),
                    ("name".to_string(), QueryParam::Text("test".to_string())),
                    (COL.to_string(), QueryParam::Integer(LIST_NUMBER)),
                ]),
            ),
            &AuthContext::new(None, space_id),
        )
        .await?;
    Ok(())
}

pub async fn server_changelog_len(transport: &LocalTransport) -> usize {
    let state = transport.state_for_tests().await;
    state.changelog.changes.len()
}
