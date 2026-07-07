use crate::db::{ServerError, SpaceState};
use crate::key_delivery::GroupKeyDeliverySlots;
use encrypted_spaces_backend::merk_storage::{FlatMerkEntries, MerkStorage};
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_changelog_core::changelog::{ChangeLog, ChangeResponse};
use encrypted_spaces_ffproof::common::FFProof;
use std::collections::{BTreeMap, HashMap};

pub struct LoadedSpaceState {
    pub db: MerkStorage,
    pub changelog: ChangeLog,
    pub change_responses: Vec<ChangeResponse>,
    pub ff_proof: Option<FFProof>,
    pub tree_snapshot: Option<merk::Node>,
    pub tree_snapshot_entries: FlatMerkEntries,
    pub sigref_map: BTreeMap<u32, u32>,
    pub hash_store: HashMap<[u8; 32], Vec<u8>>,
    pub key_delivery_slots: GroupKeyDeliverySlots,
}

/// Optional restart-durable persistence for a server Space's in-memory state.
///
/// The live query/proof engine still runs against in-memory Merk. This trait is
/// only for adapters that save and restore that server state across restarts.
/// Implementations may persist sensitive per-space material, including
/// changelog witnesses, hash-backed value sidecars, and pending group-key
/// delivery envelopes; operators should protect adapter storage like
/// application data.
///
/// Implementations must provide atomic replacement semantics for [`Self::save`],
/// read-after-write consistency for a single logical writer per Space, and
/// fail-closed validation when loading corrupt or mismatched state.
pub trait DurableSpaceStateStore: Send + Sync {
    fn state_exists(&self) -> bool;

    fn load(&self, expected_space_id: SpaceId) -> Result<Option<LoadedSpaceState>, ServerError>;

    fn save(&self, state: &SpaceState) -> Result<(), ServerError>;
}
