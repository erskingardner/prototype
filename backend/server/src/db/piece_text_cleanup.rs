//! Server-produced PieceText cleanup (Stage 4).
//!
//! Cleanup is split into two unsigned system-source changelog ops, both produced
//! only by this module — user-submitted cleanup of either kind is rejected by
//! `SpaceState::handle_change`. This module builds the envelopes from current
//! tree state and applies them through the same proof-producing storage path as
//! other changes, so clients accept them after the core verifier re-derives
//! every write from authenticated tree state:
//!
//! - `PieceTextCleanupPieces` physically removes already-tombstoned
//!   `_piecetext_pieces` rows and relinks the surviving chain. Its verifier
//!   (`PieceTextCleanupPiecesOp`) authenticates the addressed parent cell and
//!   re-derives all deletes/relinks from local linked-list splices, without
//!   scanning the whole document.
//! - `PieceTextCleanupBuffers` physically deletes `_piecetext_buffers` rows once piece
//!   cleanup has removed every `_piecetext_pieces.buffer_id` index reference to
//!   them. Its verifier (`PieceTextCleanupBuffersOp`) proves that index range is
//!   empty (a post-piece-cleanup pre-state check) and validates `_piecetext_buffers` owner
//!   metadata against the envelope address.
//!
//! ## Scheduling
//!
//! After a `PieceTextEdit` pushes a document's tombstone count over
//! `CLEANUP_THRESHOLD`, a delayed pass commits piece-cleanup chunks first, then
//! — for the buffers the removed pieces referenced whose
//! `_piecetext_pieces.buffer_id` index range is now empty — buffer-cleanup chunks.
//! Both op types are broadcast to connected clients. The candidate buffers are
//! prefiltered against the post-piece-cleanup index so we never submit a buffer
//! cleanup the verifier would reject for a still-referenced buffer.
//!
//! Temporary orphan buffers between the two phases are acceptable: per
//! `PLAN_CLEANUP_OPTIMIZE.md` they are storage overhead only, and a deferred or
//! failed buffer cleanup is late but never wrong because the empty-range proof
//! is monotonic. Buffer chunks are capped at
//! `MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS` per op (reduced from 256 after the
//! Stage 3a measurement found a 256-buffer empty-range proof exceeded the
//! 128 KiB per-change cleanup budget).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use encrypted_spaces_backend::internal_schemas::PIECE_COORDS_TABLE_NAME;
use encrypted_spaces_backend::merk_storage::{parse_key, stored_value, ParsedKey};
use encrypted_spaces_backend::proto;
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeResponse, ChangelogEntry, HashedValues, LogMessage,
};
use encrypted_spaces_changelog_core::piece_text::{
    PieceTextAddress, MAX_PIECETEXT_PIECES_PER_DOCUMENT,
};
use encrypted_spaces_changelog_core::piece_text_cleanup::{
    PieceTextCleanupBuffersEnvelopeV1, PieceTextCleanupPiecesEnvelopeV1, PieceTextCleanupRunV1,
    MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS, MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS,
    MAX_PIECE_TEXT_CLEANUP_RUNS, PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
};
use encrypted_spaces_storage_encoding::keys;
use encrypted_spaces_storage_encoding::TupleElement;

use super::{ServerError, SpaceState};

const CLEANUP_DELAY: Duration = Duration::from_secs(5);
const CLEANUP_THRESHOLD: u32 = 100;

#[derive(Default)]
pub(super) struct ChainCleanup {
    count: u32,
    pending: bool,
    /// Buffers orphaned by piece cleanup that the buffer-cleanup phase has not
    /// yet deleted (it failed or was interrupted mid-chunk). Carried across
    /// cleanup passes so a later pass retries them instead of leaking them — the
    /// empty-range proof is monotonic, so a retry stays valid.
    pending_buffers: BTreeSet<i64>,
}

pub(super) type ChainKey = (PieceTextAddress, i64);

pub(crate) type BroadcastCleanupFn = Arc<
    dyn Fn(SpaceId, proto::Broadcast) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

#[derive(Default)]
pub(crate) struct CleanupState {
    chains: HashMap<ChainKey, ChainCleanup>,
    pub(crate) auto_cleanup_enabled: bool,
}

impl CleanupState {
    pub(crate) fn clear_pending(&mut self) {
        self.chains.clear();
    }
}

#[derive(Default)]
struct CleanupOutcome {
    broadcasts: Vec<(ChangelogEntry, ChangeResponse)>,
    error: Option<ServerError>,
}

/// One `_piecetext_pieces` row as seen while walking the document chain in
/// head -> tail order. The walk follows `next_id` pointers, so the row's own
/// `next_id` is only needed transiently and is not retained here. `buffer_id` is
/// retained so the scheduler can identify the buffers that removed (tombstoned)
/// rows reference, as candidates for the second-phase buffer cleanup.
#[derive(Debug, Clone)]
struct CleanupChainRow {
    id: i64,
    tombstone: bool,
    buffer_id: i64,
}

impl SpaceState {
    pub(crate) fn maybe_schedule_piece_text_cleanup(
        &mut self,
        address: PieceTextAddress,
        list_number: i64,
        reconciled_tombstones: u32,
    ) {
        if !self.cleanup_state.auto_cleanup_enabled || list_number <= 0 {
            return;
        }

        let chain_key: ChainKey = (address, list_number);
        // Orphan-buffer retry state must survive a reconciliation that reports no
        // tombstones — otherwise a later edit erases buffers still awaiting
        // deletion. A chain with pending orphan buffers stays live regardless of
        // the tombstone count.
        let has_pending_buffers = self
            .cleanup_state
            .chains
            .get(&chain_key)
            .map(|entry| !entry.pending_buffers.is_empty())
            .unwrap_or(false);

        if reconciled_tombstones == 0 && !has_pending_buffers {
            self.cleanup_state.chains.remove(&chain_key);
            return;
        }

        let should_spawn = {
            let entry = self
                .cleanup_state
                .chains
                .entry(chain_key.clone())
                .or_default();
            entry.count = reconciled_tombstones;
            // Spawn a pass when there are enough tombstones to clean, or when
            // orphan buffers are awaiting retry (a pass drains them even at
            // count 0).
            if (entry.count >= CLEANUP_THRESHOLD || !entry.pending_buffers.is_empty())
                && !entry.pending
            {
                entry.pending = true;
                true
            } else {
                false
            }
        };

        if !should_spawn {
            let retain = self
                .cleanup_state
                .chains
                .get(&chain_key)
                .map(|entry| entry.pending || !entry.pending_buffers.is_empty())
                .unwrap_or(false);
            if !retain {
                self.cleanup_state.chains.remove(&chain_key);
            }
        }

        if should_spawn {
            self.spawn_piece_text_cleanup_check(chain_key);
        }
    }

    fn spawn_piece_text_cleanup_check(&self, chain_key: ChainKey) {
        let space_id = self.space_id;
        tokio::spawn(async move {
            tokio::time::sleep(CLEANUP_DELAY).await;
            let Some(space) = super::try_get_loaded_space(space_id).await else {
                return;
            };

            let (outcome, broadcast_cleanup) = {
                let mut state = space.lock().await;
                let outcome = state.run_piece_text_cleanup(chain_key).await;
                (outcome, state.broadcast_cleanup.clone())
            };

            if let Some(callback) = broadcast_cleanup {
                for (change, response) in outcome.broadcasts {
                    callback(
                        space_id,
                        proto::Broadcast {
                            change_entry: Some((&change).into()),
                            change_response: Some(proto::ChangeResponse::from(&response)),
                        },
                    )
                    .await;
                }
            }

            if let Some(e) = outcome.error {
                log::error!("space={space_id} piece-text cleanup failed: {e}");
            }
        });
    }

    pub(crate) fn read_piece_text_list_number_for_cleanup(
        &self,
        address: &PieceTextAddress,
    ) -> Result<i64, ServerError> {
        read_i64_column(&self.db, &address.table, address.row_id, &address.column)
    }

    pub(crate) fn count_tombstone_rows_for_list(
        &self,
        list_number: i64,
    ) -> Result<u32, ServerError> {
        let prefix = keys::index_value_prefix(PIECE_COORDS_TABLE_NAME, "list_number", list_number)
            .map_err(|e| {
                ServerError::Generic(format!(
                    "failed to build _piecetext_pieces list_number index prefix: {e}"
                ))
            })?;
        let entries = self.db.iter_prefix_entries(&prefix).map_err(|e| {
            ServerError::Generic(format!(
                "failed to scan _piecetext_pieces list_number={list_number} index: {e}"
            ))
        })?;
        let mut count = 0usize;
        for (key, value) in entries {
            let row_id = decode_piece_coords_list_index_row_id(&key, &value, list_number)?;
            let tombstone_raw =
                read_i64_column(&self.db, PIECE_COORDS_TABLE_NAME, row_id, "tombstone")?;
            match tombstone_raw {
                0 => {}
                1 => count += 1,
                other => {
                    return Err(ServerError::Generic(format!(
                        "piece-text cleanup: _piecetext_pieces row {row_id} has invalid tombstone {other}"
                    )));
                }
            }
        }
        u32::try_from(count).map_err(|_| {
            ServerError::Generic(format!(
                "piece-text cleanup tombstone count {count} exceeds u32 range"
            ))
        })
    }

    fn build_cleanup_changelog_entry(
        &self,
        message: LogMessage,
    ) -> Result<ChangelogEntry, ServerError> {
        let parent_change = self.changelog.num_changes();
        let parent_clc = self.changelog.root_at(parent_change).ok_or_else(|| {
            ServerError::Generic(format!(
                "cleanup parent_change {parent_change} has no changelog root"
            ))
        })?;
        Ok(ChangelogEntry {
            timestamp: ChangelogEntry::get_unix_timestamp(),
            uid: 0,
            parent_change,
            message,
            sig_ref: 0,
            parent_clc,
            signature: vec![],
        })
    }

    /// Commit one cleanup chunk (piece or buffer) as an unsigned system entry
    /// through the same proof-producing storage path as a user change. `address`
    /// is the document the chunk belongs to, used only for the post-commit debug
    /// invariant self-check.
    async fn commit_cleanup_chunk(
        &mut self,
        message: LogMessage,
        address: &PieceTextAddress,
    ) -> Result<(ChangelogEntry, ChangeResponse), ServerError> {
        let num_changes = self.changelog.num_changes() as usize;
        if num_changes == self.changelog.proven_up_to {
            self.tree_snapshot = self.db.snapshot();
        }

        let current_change_id = self.changelog.num_changes() as usize + 1;
        let entry = self.build_cleanup_changelog_entry(message)?;
        self.ensure_change_applies(&entry)?;
        let change = Change {
            entry: entry.clone(),
            hashed_values: HashedValues::new(),
        };

        let old_root = self.get_root_hash().await;
        let pruned_merkle_tree = self
            .db
            .apply_change_with_pruned_tree(&change, current_change_id)
            .await
            .map_err(|e| ServerError::Generic(format!("piece-text cleanup apply failed: {e}")))?;
        let new_root = self.get_root_hash().await;

        let change_id =
            self.changelog
                .add_change(&entry, &pruned_merkle_tree, &old_root, &new_root)?;

        // Post-commit self-check (debug only, log-only): re-derive the document
        // and assert its `_piecetext_pieces` / `_piecetext_buffers` structure is internally
        // consistent after the splice. The signed verifier already enforced
        // these properties; this is defence-in-depth. Orphan `_piecetext_buffers` rows
        // left by piece cleanup are tolerated — the scan only validates buffers
        // that surviving pieces reference.
        #[cfg(debug_assertions)]
        if let Err(e) = self.assert_piece_text_invariants(address) {
            log::error!(
                "space={} piece-text invariants violated post-cleanup \
                 (table={}, row_id={}, column={}, change_id={}): {e}",
                self.space_id,
                address.table,
                address.row_id,
                address.column,
                change_id,
            );
        }

        let accepted_at_server_time = ChangelogEntry::get_unix_timestamp();
        let response = ChangeResponse {
            old_root,
            new_root,
            pruned_merkle_tree,
            change_id,
            rows_affected: 1,
            accepted_at_server_time,
            hashed_values: HashedValues::new(),
        };
        self.change_responses.push(response.clone());

        Ok((entry, response))
    }

    async fn run_piece_text_cleanup(&mut self, chain_key: ChainKey) -> CleanupOutcome {
        let outcome = self.run_piece_text_cleanup_inner(&chain_key).await;
        let committed_chunks = outcome.broadcasts.len();

        let mut remove_chain = false;
        let respawn = {
            if let Some(entry) = self.cleanup_state.chains.get_mut(&chain_key) {
                entry.pending = false;
                if !entry.pending_buffers.is_empty() {
                    // Orphan buffers still await deletion (buffer cleanup failed
                    // or was partial). Keep the chain and retry on a later tick —
                    // but only if this pass made progress, otherwise leave them
                    // pending for the next edit-triggered cleanup so a persistent
                    // error does not spin a tight retry loop.
                    if committed_chunks > 0 {
                        entry.pending = true;
                        true
                    } else {
                        false
                    }
                } else if entry.count == 0 {
                    remove_chain = true;
                    false
                } else if committed_chunks > 0 && entry.count >= CLEANUP_THRESHOLD {
                    entry.pending = true;
                    true
                } else if entry.count < CLEANUP_THRESHOLD {
                    remove_chain = true;
                    false
                } else {
                    false
                }
            } else {
                false
            }
        };
        if remove_chain {
            self.cleanup_state.chains.remove(&chain_key);
        }

        if respawn {
            self.spawn_piece_text_cleanup_check(chain_key);
        }

        outcome
    }

    async fn run_piece_text_cleanup_inner(&mut self, chain_key: &ChainKey) -> CleanupOutcome {
        let (count, prior_pending_buffers) = self
            .cleanup_state
            .chains
            .get(chain_key)
            .map(|entry| (entry.count, entry.pending_buffers.clone()))
            .unwrap_or((0, BTreeSet::new()));
        // Nothing to do: not enough tombstones for a piece pass, and no orphan
        // buffers left over from a prior failed buffer pass.
        if count < CLEANUP_THRESHOLD && prior_pending_buffers.is_empty() {
            return CleanupOutcome::default();
        }

        let (address, list_number) = chain_key;
        let mut broadcasts = Vec::new();
        // Buffers to delete this pass: orphans carried over from a prior pass,
        // plus any newly orphaned by Phase 1 below.
        let mut candidate_buffers = prior_pending_buffers;

        // Phase 1: physically remove tombstoned `_piecetext_pieces` rows (only when
        // there are enough tombstones to be worth a pass). Each chunk commits and
        // broadcasts before the next is built, so later chunks validate against
        // the chain state the earlier ones left.
        if count >= CLEANUP_THRESHOLD {
            let (chunks, fresh_candidates) = match self.build_cleanup_chunks(address, *list_number)
            {
                Ok(result) => result,
                Err(e) => {
                    return CleanupOutcome {
                        broadcasts,
                        error: Some(e),
                    }
                }
            };
            for envelope in &chunks {
                let message = match envelope.changelog_message() {
                    Ok(message) => message,
                    Err(e) => {
                        return CleanupOutcome {
                            broadcasts,
                            error: Some(ServerError::Generic(format!(
                                "piece cleanup changelog_message: {e}"
                            ))),
                        }
                    }
                };
                let (change, response) = match self.commit_cleanup_chunk(message, address).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        return CleanupOutcome {
                            broadcasts,
                            error: Some(e),
                        }
                    }
                };
                let removed: usize = envelope.runs.iter().map(|run| run.removals.len()).sum();
                let cleaned = u32::try_from(removed).unwrap_or(u32::MAX);
                if let Some(entry) = self.cleanup_state.chains.get_mut(chain_key) {
                    entry.count = entry.count.saturating_sub(cleaned);
                }
                broadcasts.push((change, response));

                if let Err(e) = self.maybe_generate_ff_proof() {
                    log::error!(
                        "space={} FF proof generation after cleanup failed (non-fatal): {e}",
                        self.space_id
                    );
                }
            }
            if let Some(entry) = self.cleanup_state.chains.get_mut(chain_key) {
                entry.count = 0;
            }
            candidate_buffers.extend(fresh_candidates);
        }

        // Phase 2: delete `_piecetext_buffers` rows for orphaned candidate buffers (their
        // `_piecetext_pieces.buffer_id` index range is now empty). Best-effort and
        // idempotent: any candidate we fail to delete is recorded as pending so a
        // later pass retries it, rather than being dropped (which would leak the
        // buffer). Committed deletes stand regardless.
        let (remaining_orphans, error) = self
            .run_buffer_cleanup_phase(address, &candidate_buffers, &mut broadcasts)
            .await;
        if let Some(entry) = self.cleanup_state.chains.get_mut(chain_key) {
            entry.pending_buffers = remaining_orphans;
        }

        CleanupOutcome { broadcasts, error }
    }

    /// Phase 2 of cleanup: delete `_piecetext_buffers` rows for the orphaned candidate
    /// buffers. Returns the candidates it did NOT manage to delete (to retry on a
    /// later pass) and the first error, if any. Still-referenced candidates are
    /// dropped (they are not orphans); successfully committed deletes are removed
    /// from the returned set so they are never retried.
    async fn run_buffer_cleanup_phase(
        &mut self,
        address: &PieceTextAddress,
        candidate_buffers: &BTreeSet<i64>,
        broadcasts: &mut Vec<(ChangelogEntry, ChangeResponse)>,
    ) -> (BTreeSet<i64>, Option<ServerError>) {
        if candidate_buffers.is_empty() {
            return (BTreeSet::new(), None);
        }
        let buffer_chunks = match self.build_buffer_cleanup_chunks(address, candidate_buffers) {
            Ok(buffer_chunks) => buffer_chunks,
            // Could not even build the chunks — every candidate is still pending.
            Err(e) => return (candidate_buffers.clone(), Some(e)),
        };
        // Buffers actually scheduled for deletion (the build prefilters to
        // empty-range ones); still-referenced candidates are left out and not
        // retried.
        let mut remaining: BTreeSet<i64> = buffer_chunks
            .iter()
            .flat_map(|chunk| chunk.buffer_removals.iter().copied())
            .collect();
        for envelope in &buffer_chunks {
            let message = match envelope.changelog_message() {
                Ok(message) => message,
                Err(e) => {
                    return (
                        remaining,
                        Some(ServerError::Generic(format!(
                            "buffer cleanup changelog_message: {e}"
                        ))),
                    )
                }
            };
            let (change, response) = match self.commit_cleanup_chunk(message, address).await {
                Ok(pair) => pair,
                Err(e) => return (remaining, Some(e)),
            };
            for &buffer_id in &envelope.buffer_removals {
                remaining.remove(&buffer_id);
            }
            broadcasts.push((change, response));

            if let Err(e) = self.maybe_generate_ff_proof() {
                log::error!(
                    "space={} FF proof generation after buffer cleanup failed (non-fatal): {e}",
                    self.space_id
                );
            }
        }
        (remaining, None)
    }

    /// Test-only: force a full piece-then-buffer cleanup pass for `(address,
    /// list_number)`, bypassing the tombstone threshold and the scheduling delay.
    /// Commits the cleanup ops to the changelog (clients pick them up on their
    /// next sync) and returns the number of cleanup changes committed. Used by the
    /// edits-and-cleanup fuzz harness; this goes through the same
    /// `commit_cleanup_chunk` path, so the verifier and the debug post-commit
    /// invariant self-check run on every chunk.
    // Used only by external test crates (the SDK edits-and-cleanup fuzz), so the
    // binary target sees no caller.
    #[allow(dead_code)]
    pub async fn force_piece_text_cleanup_for_tests(
        &mut self,
        address: &PieceTextAddress,
        list_number: i64,
    ) -> Result<usize, ServerError> {
        let (chunks, candidate_buffers) = self.build_cleanup_chunks(address, list_number)?;
        let mut committed = 0usize;
        for envelope in &chunks {
            let message = envelope.changelog_message().map_err(|e| {
                ServerError::Generic(format!("piece cleanup changelog_message: {e}"))
            })?;
            self.commit_cleanup_chunk(message, address).await?;
            committed += 1;
        }
        let buffer_chunks = self.build_buffer_cleanup_chunks(address, &candidate_buffers)?;
        for envelope in &buffer_chunks {
            let message = envelope.changelog_message().map_err(|e| {
                ServerError::Generic(format!("buffer cleanup changelog_message: {e}"))
            })?;
            self.commit_cleanup_chunk(message, address).await?;
            committed += 1;
        }
        Ok(committed)
    }

    /// Build the `PieceTextCleanupPieces` envelopes that physically remove every
    /// tombstoned `_piecetext_pieces` row for `list_number`.
    ///
    /// Walks the chain in head -> tail order, groups maximal contiguous runs of
    /// tombstoned rows (bracketed by their surviving neighbours, or the head /
    /// tail sentinel `0`), and packs those runs into chunks that satisfy the V1
    /// disjoint-splice predicate enforced by `PieceTextCleanupPiecesEnvelopeV1`:
    ///
    /// - at most `MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS` removed rows per chunk;
    /// - at most `MAX_PIECE_TEXT_CLEANUP_RUNS` runs per chunk;
    /// - no boundary survivor reused by two runs in the same chunk (so two
    ///   contiguous runs separated by a single live row land in different
    ///   chunks);
    /// - a run that splits one long contiguous tombstone run (because it exceeds
    ///   the removal cap) names the next tombstone as its boundary and the
    ///   remainder goes to a later chunk — never the same one, where the boundary
    ///   tombstone would also be a removal.
    ///
    /// Chunks commit sequentially, so a later chunk's runs are validated against
    /// the chain state left by the earlier chunks.
    ///
    /// Returns the piece-cleanup envelopes together with the set of `buffer_id`s
    /// the removed (tombstoned) rows reference. Those are the candidate buffers
    /// for second-phase buffer cleanup; a candidate is only actually deleted once
    /// piece cleanup has emptied its `_piecetext_pieces.buffer_id` index range (a
    /// buffer shared with a surviving live piece stays referenced and is skipped).
    fn build_cleanup_chunks(
        &self,
        address: &PieceTextAddress,
        list_number: i64,
    ) -> Result<(Vec<PieceTextCleanupPiecesEnvelopeV1>, BTreeSet<i64>), ServerError> {
        let chain = self.read_piece_chain_rows(list_number)?;

        // Buffers referenced by the rows we are about to remove; candidates for
        // the buffer-cleanup phase once their index range is empty.
        let candidate_buffers: BTreeSet<i64> = chain
            .iter()
            .filter(|row| row.tombstone && row.buffer_id > 0)
            .map(|row| row.buffer_id)
            .collect();

        // Maximal contiguous tombstone runs with their surviving boundaries.
        let mut macro_runs: Vec<CleanupRunSlice> = Vec::new();
        let mut prev_survivor = 0i64; // 0 == before head
        let mut idx = 0usize;
        while idx < chain.len() {
            if chain[idx].tombstone {
                let mut removals = Vec::new();
                while idx < chain.len() && chain[idx].tombstone {
                    removals.push(chain[idx].id);
                    idx += 1;
                }
                // Surviving row after the run, or 0 (after tail) if it runs off
                // the end of the chain.
                let next_survivor = if idx < chain.len() { chain[idx].id } else { 0 };
                macro_runs.push(CleanupRunSlice {
                    prev_survivor,
                    removals,
                    next_survivor,
                });
            } else {
                prev_survivor = chain[idx].id;
                idx += 1;
            }
        }
        if macro_runs.is_empty() {
            return Ok((Vec::new(), candidate_buffers));
        }

        let removal_cap = MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS;
        let run_cap = MAX_PIECE_TEXT_CLEANUP_RUNS;

        let mut chunks: Vec<Vec<CleanupRunSlice>> = Vec::new();
        let mut cur: Vec<CleanupRunSlice> = Vec::new();
        let mut cur_removals = 0usize;
        let mut cur_boundaries: HashSet<i64> = HashSet::new();

        for macro_run in macro_runs {
            let prev = macro_run.prev_survivor;
            let total = macro_run.removals.len();
            let mut start = 0usize;
            loop {
                let remaining = total - start;
                if remaining == 0 {
                    break;
                }
                if cur.len() == run_cap {
                    flush_chunk(
                        &mut chunks,
                        &mut cur,
                        &mut cur_removals,
                        &mut cur_boundaries,
                    );
                }
                let avail = removal_cap - cur_removals;
                if avail == 0 {
                    flush_chunk(
                        &mut chunks,
                        &mut cur,
                        &mut cur_removals,
                        &mut cur_boundaries,
                    );
                    continue;
                }
                let take = remaining.min(avail);
                let is_split = take < remaining;
                let next = if is_split {
                    macro_run.removals[start + take]
                } else {
                    macro_run.next_survivor
                };

                // A boundary survivor must be unique within a chunk. The only
                // realistic collision is `prev` equalling the previous run's
                // `next` (a single live row between two tombstone runs); flush so
                // they land in separate chunks.
                let prev_conflict = prev != 0 && cur_boundaries.contains(&prev);
                let next_conflict = next != 0 && cur_boundaries.contains(&next);
                if !cur.is_empty() && (prev_conflict || next_conflict) {
                    flush_chunk(
                        &mut chunks,
                        &mut cur,
                        &mut cur_removals,
                        &mut cur_boundaries,
                    );
                    continue;
                }

                cur.push(CleanupRunSlice {
                    prev_survivor: prev,
                    removals: macro_run.removals[start..start + take].to_vec(),
                    next_survivor: next,
                });
                cur_removals += take;
                if prev != 0 {
                    cur_boundaries.insert(prev);
                }
                if next != 0 {
                    cur_boundaries.insert(next);
                }
                start += take;

                if is_split {
                    // The remainder shares `prev` and names this chunk's
                    // boundary tombstone as a removal, so it must go to a fresh
                    // chunk.
                    flush_chunk(
                        &mut chunks,
                        &mut cur,
                        &mut cur_removals,
                        &mut cur_boundaries,
                    );
                }
            }
        }
        flush_chunk(
            &mut chunks,
            &mut cur,
            &mut cur_removals,
            &mut cur_boundaries,
        );

        // Assign op ids and canonicalise run order. Chunks commit consecutively
        // starting at the next change id, so chunk `i`'s op_id is that id plus
        // the number of chunks committed before it.
        let base_change_id = self.changelog.num_changes() as i64 + 1;
        let mut envelopes = Vec::with_capacity(chunks.len());
        for (i, mut slices) in chunks.into_iter().enumerate() {
            // Canonical order is by first removed row id (unique per run after
            // dedup). The survivors are dropped from the wire here; the verifier
            // re-derives them from the rows.
            slices.sort_by_key(|slice| slice.removals[0]);
            let runs: Vec<PieceTextCleanupRunV1> = slices
                .into_iter()
                .map(|slice| PieceTextCleanupRunV1 {
                    removals: slice.removals,
                })
                .collect();
            let envelope = PieceTextCleanupPiecesEnvelopeV1 {
                version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
                address: address.clone(),
                list_number,
                op_id: base_change_id + i as i64,
                runs,
            };
            // Defence in depth: reject a malformed chunk before committing it.
            envelope.validate_shape().map_err(|e| {
                ServerError::Generic(format!(
                    "piece-text cleanup produced an invalid chunk for list {list_number}: {e}"
                ))
            })?;
            envelopes.push(envelope);
        }
        Ok((envelopes, candidate_buffers))
    }

    /// Build the `PieceTextCleanupBuffers` envelopes that physically delete the
    /// `_piecetext_buffers` rows for the orphaned candidate buffers.
    ///
    /// `candidate_buffers` are the buffers referenced by the rows that piece
    /// cleanup removed. This prefilters them to those whose
    /// `_piecetext_pieces.buffer_id` index range is now empty — i.e. no surviving
    /// piece (in this or any document) still references them — so the verifier's
    /// empty-range proof succeeds. A buffer still referenced by a live piece is
    /// silently skipped and left in place. Eligible buffers are emitted in
    /// ascending order, chunked at `MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS`.
    ///
    /// Must be called only after every piece-cleanup chunk for the document has
    /// committed, so the index ranges reflect the post-piece-cleanup state. Op
    /// ids are assigned from the current change id on the assumption that these
    /// chunks commit consecutively next.
    fn build_buffer_cleanup_chunks(
        &self,
        address: &PieceTextAddress,
        candidate_buffers: &BTreeSet<i64>,
    ) -> Result<Vec<PieceTextCleanupBuffersEnvelopeV1>, ServerError> {
        let mut eligible: Vec<i64> = Vec::new();
        for &buffer_id in candidate_buffers {
            if buffer_id <= 0 {
                continue;
            }
            if self.piece_coords_buffer_range_is_empty(buffer_id)? {
                eligible.push(buffer_id);
            }
        }
        if eligible.is_empty() {
            return Ok(Vec::new());
        }
        // `candidate_buffers` is a `BTreeSet`, so `eligible` is already ascending
        // and unique as the buffer envelope requires.

        let base_change_id = self.changelog.num_changes() as i64 + 1;
        let mut envelopes = Vec::new();
        for (i, chunk) in eligible
            .chunks(MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS)
            .enumerate()
        {
            let envelope = PieceTextCleanupBuffersEnvelopeV1 {
                version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
                address: address.clone(),
                op_id: base_change_id + i as i64,
                buffer_removals: chunk.to_vec(),
            };
            // Defence in depth: reject a malformed chunk before committing it.
            envelope.validate_shape().map_err(|e| {
                ServerError::Generic(format!(
                    "piece-text cleanup produced an invalid buffer chunk: {e}"
                ))
            })?;
            envelopes.push(envelope);
        }
        Ok(envelopes)
    }

    /// True when no `_piecetext_pieces.buffer_id` index entry references `buffer_id`
    /// — the same emptiness the buffer-cleanup verifier proves, checked locally
    /// (server reads, no proof) to prefilter cleanup candidates.
    fn piece_coords_buffer_range_is_empty(&self, buffer_id: i64) -> Result<bool, ServerError> {
        let prefix = keys::index_value_prefix(PIECE_COORDS_TABLE_NAME, "buffer_id", buffer_id)
            .map_err(|e| {
                ServerError::Generic(format!(
                    "failed to build _piecetext_pieces buffer_id index prefix: {e}"
                ))
            })?;
        let has_any = self.db.prefix_has_any(&prefix).map_err(|e| {
            ServerError::Generic(format!(
                "failed to scan _piecetext_pieces buffer_id={buffer_id} index: {e}"
            ))
        })?;
        Ok(!has_any)
    }

    /// Walk the `_piecetext_pieces` chain for `list_number` from head to tail,
    /// returning every row (live and tombstoned) in chain order.
    fn read_piece_chain_rows(&self, list_number: i64) -> Result<Vec<CleanupChainRow>, ServerError> {
        let head_id = read_be_i64_key(
            &self.db,
            &keys::piece_coords_head_key(list_number),
            "piece_coords head",
        )?;
        let tail_id = read_be_i64_key(
            &self.db,
            &keys::piece_coords_tail_key(list_number),
            "piece_coords tail",
        )?;

        let mut rows = Vec::new();
        let mut current = head_id;
        while current != 0 {
            // The document piece cap bounds the chain length; exceeding it means
            // a corrupted (e.g. cyclic) chain, which we refuse to clean.
            if rows.len() >= MAX_PIECETEXT_PIECES_PER_DOCUMENT {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list {list_number} chain exceeds {MAX_PIECETEXT_PIECES_PER_DOCUMENT} rows (corrupt or cyclic)"
                )));
            }
            let row_list =
                read_i64_column(&self.db, PIECE_COORDS_TABLE_NAME, current, "list_number")?;
            if row_list != list_number {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: chain row {current} belongs to list {row_list}, expected {list_number}"
                )));
            }
            let next_id = read_i64_column(&self.db, PIECE_COORDS_TABLE_NAME, current, "next_id")?;
            let buffer_id =
                read_i64_column(&self.db, PIECE_COORDS_TABLE_NAME, current, "buffer_id")?;
            let tombstone_raw =
                read_i64_column(&self.db, PIECE_COORDS_TABLE_NAME, current, "tombstone")?;
            let tombstone = match tombstone_raw {
                0 => false,
                1 => true,
                other => {
                    return Err(ServerError::Generic(format!(
                        "piece-text cleanup: _piecetext_pieces row {current} has invalid tombstone {other}"
                    )));
                }
            };
            rows.push(CleanupChainRow {
                id: current,
                tombstone,
                buffer_id,
            });
            current = next_id;
        }

        // Cross-check head/tail consistency against the walked chain.
        match rows.last() {
            Some(last) if last.id != tail_id => {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list {list_number} chain ends at row {} but tail is {tail_id}",
                    last.id
                )));
            }
            None if tail_id != 0 => {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list {list_number} chain is empty but tail is {tail_id}"
                )));
            }
            _ => {}
        }

        Ok(rows)
    }
}

/// Internal chunking representation: a contiguous tombstone run together with
/// its surviving boundaries. The boundaries are needed to decide chunk splits
/// (a survivor must not be reused or removed within a chunk), but are NOT put on
/// the wire — the emitted `PieceTextCleanupRunV1` carries only `removals`, and
/// the verifier re-derives the survivors from the rows.
struct CleanupRunSlice {
    prev_survivor: i64,
    removals: Vec<i64>,
    next_survivor: i64,
}

/// Push the current chunk's runs into `chunks` and reset the accumulators. A
/// no-op when the chunk is empty, so callers can flush unconditionally.
fn flush_chunk(
    chunks: &mut Vec<Vec<CleanupRunSlice>>,
    cur: &mut Vec<CleanupRunSlice>,
    cur_removals: &mut usize,
    cur_boundaries: &mut HashSet<i64>,
) {
    if !cur.is_empty() {
        chunks.push(std::mem::take(cur));
        *cur_removals = 0;
        cur_boundaries.clear();
    }
}

fn decode_piece_coords_list_index_row_id(
    key: &[u8],
    value: &[u8],
    expected_list_number: i64,
) -> Result<i64, ServerError> {
    match parse_key(key) {
        Ok(ParsedKey::Index {
            table,
            column,
            value: index_value,
            row_id,
        }) => {
            if table != PIECE_COORDS_TABLE_NAME || column != "list_number" {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list_number prefix returned index for {table}.{column}"
                )));
            }
            if index_value != TupleElement::Int(expected_list_number) {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list_number index returned value {index_value:?}, expected {expected_list_number}"
                )));
            }
            if row_id <= 0 {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list_number index returned non-positive row id {row_id}"
                )));
            }
            if value != keys::row_id_to_bytes(row_id) {
                return Err(ServerError::Generic(format!(
                    "piece-text cleanup: list_number index entry for row {row_id} has wrong value"
                )));
            }
            Ok(row_id)
        }
        Ok(other) => Err(ServerError::Generic(format!(
            "piece-text cleanup: list_number prefix returned non-index key {other:?}"
        ))),
        Err(e) => Err(ServerError::Generic(format!(
            "piece-text cleanup: failed to parse list_number index key: {e}"
        ))),
    }
}

fn read_be_i64_key(
    db: &encrypted_spaces_backend::merk_storage::MerkStorage,
    key: &[u8],
    label: &str,
) -> Result<i64, ServerError> {
    let bytes = db.get_value(key)?.ok_or_else(|| {
        ServerError::Generic(format!("piece-text cleanup: {label} key is absent"))
    })?;
    let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
        ServerError::Generic(format!(
            "piece-text cleanup: {label} key has {} bytes, expected 8",
            bytes.len()
        ))
    })?;
    Ok(i64::from_be_bytes(arr))
}

fn read_i64_column(
    db: &encrypted_spaces_backend::merk_storage::MerkStorage,
    table: &str,
    row_id: i64,
    column: &str,
) -> Result<i64, ServerError> {
    let key = keys::column_key(table, row_id, column);
    let bytes = db.get_value(&key)?.ok_or_else(|| {
        ServerError::Generic(format!(
            "piece-text cleanup: {table}.{row_id}.{column} is absent"
        ))
    })?;
    let value = stored_value::bytes_to_value(&bytes).map_err(|e| {
        ServerError::Generic(format!(
            "piece-text cleanup: failed to decode {table}.{row_id}.{column}: {e}"
        ))
    })?;
    value.as_i64().ok_or_else(|| {
        ServerError::Generic(format!(
            "piece-text cleanup: {table}.{row_id}.{column} is not an integer"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::access_control::AuthContext;
    use encrypted_spaces_backend::internal_schemas::BUFFERS_TABLE_NAME;
    use encrypted_spaces_backend::merk_storage::Op;
    use encrypted_spaces_changelog_core::changelog::OpType;
    use encrypted_spaces_changelog_core::piece_text_cleanup::PieceTextCleanupBuffersEnvelopeV1;
    use std::collections::BTreeSet;

    fn stored_test_i64(value: i64) -> Vec<u8> {
        stored_value::value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn stored_test_string(value: &str) -> Vec<u8> {
        stored_value::value_to_bytes(&serde_json::json!(value)).unwrap()
    }

    fn cleanup_chunk_test_state() -> (SpaceState, PieceTextAddress) {
        let state = futures::executor::block_on(SpaceState::init_server(None, None, None)).unwrap();
        let address = PieceTextAddress {
            table: "docs".to_string(),
            row_id: 1,
            column: "body".to_string(),
        };
        (state, address)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_synthetic_piece_row(
        state: &SpaceState,
        row_id: i64,
        list_number: i64,
        buffer_id: i64,
        start_byte: i64,
        tombstone: bool,
        prev_id: i64,
        next_id: i64,
    ) {
        let ops = vec![
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "list_number"),
                Op::Put(stored_test_i64(list_number)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "prev_id"),
                Op::Put(stored_test_i64(prev_id)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "next_id"),
                Op::Put(stored_test_i64(next_id)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "buffer_id"),
                Op::Put(stored_test_i64(buffer_id)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "start_byte"),
                Op::Put(stored_test_i64(start_byte)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "len_bytes"),
                Op::Put(stored_test_i64(4)),
            ),
            (
                keys::column_key(PIECE_COORDS_TABLE_NAME, row_id, "tombstone"),
                Op::Put(stored_test_i64(if tombstone { 1 } else { 0 })),
            ),
            (
                keys::index_key(PIECE_COORDS_TABLE_NAME, "list_number", list_number, row_id)
                    .unwrap(),
                Op::Put(keys::row_id_to_bytes(row_id).to_vec()),
            ),
            (
                keys::index_key(PIECE_COORDS_TABLE_NAME, "buffer_id", buffer_id, row_id).unwrap(),
                Op::Put(keys::row_id_to_bytes(row_id).to_vec()),
            ),
        ];
        state.db.apply_batch_ops(ops).unwrap();
    }

    fn write_synthetic_piece_text_parent(
        state: &SpaceState,
        address: &PieceTextAddress,
        list_number: i64,
        head_id: i64,
        tail_id: i64,
    ) {
        let mut piece_text_columns = BTreeSet::new();
        piece_text_columns.insert(address.column.clone());
        state
            .db
            .apply_batch_ops(vec![
                (
                    keys::schema_piece_text_columns_key(&address.table),
                    Op::Put(encrypted_spaces_storage_encoding::encode_column_names(
                        &piece_text_columns,
                    )),
                ),
                (
                    keys::column_key(&address.table, address.row_id, &address.column),
                    Op::Put(stored_test_i64(list_number)),
                ),
                (
                    keys::piece_coords_parent_key(list_number),
                    Op::Put(keys::encode_list_parent(
                        &address.table,
                        address.row_id,
                        &address.column,
                    )),
                ),
                (
                    keys::piece_coords_head_key(list_number),
                    Op::Put(head_id.to_be_bytes().to_vec()),
                ),
                (
                    keys::piece_coords_tail_key(list_number),
                    Op::Put(tail_id.to_be_bytes().to_vec()),
                ),
            ])
            .unwrap();
    }

    fn write_synthetic_buffer_row(
        state: &SpaceState,
        address: &PieceTextAddress,
        buffer_id: i64,
        len_bytes: i64,
    ) {
        let ops = vec![
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "owner_table"),
                Op::Put(stored_test_string(&address.table)),
            ),
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "owner_row_id"),
                Op::Put(stored_test_i64(address.row_id)),
            ),
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "owner_column"),
                Op::Put(stored_test_string(&address.column)),
            ),
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "author_id"),
                Op::Put(stored_test_i64(1)),
            ),
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "len_bytes"),
                Op::Put(stored_test_i64(len_bytes)),
            ),
            (
                keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "contents"),
                Op::Put(vec![0u8; 32]),
            ),
            (
                keys::index_key(
                    BUFFERS_TABLE_NAME,
                    "owner_table",
                    address.table.clone(),
                    buffer_id,
                )
                .unwrap(),
                Op::Put(keys::row_id_to_bytes(buffer_id).to_vec()),
            ),
            (
                keys::index_key(
                    BUFFERS_TABLE_NAME,
                    "owner_row_id",
                    address.row_id,
                    buffer_id,
                )
                .unwrap(),
                Op::Put(keys::row_id_to_bytes(buffer_id).to_vec()),
            ),
            (
                keys::index_key(
                    BUFFERS_TABLE_NAME,
                    "owner_column",
                    address.column.clone(),
                    buffer_id,
                )
                .unwrap(),
                Op::Put(keys::row_id_to_bytes(buffer_id).to_vec()),
            ),
        ];
        state.db.apply_batch_ops(ops).unwrap();
    }

    /// Two contiguous tombstone runs separated by *two* live rows produce two
    /// disjoint splice runs that share no boundary survivor, so they pack into a
    /// single chunk in canonical order.
    #[test]
    fn build_cleanup_chunks_groups_disjoint_runs_in_one_chunk() {
        let (state, address) = cleanup_chunk_test_state();
        let list = 1;
        // chain: 1(live) 2(tomb) 3(live) 4(live) 5(tomb) 6(live)
        write_synthetic_piece_text_parent(&state, &address, list, 1, 6);
        write_synthetic_piece_row(&state, 1, list, 1, 0, false, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 0, true, 1, 3);
        write_synthetic_piece_row(&state, 3, list, 1, 0, false, 2, 4);
        write_synthetic_piece_row(&state, 4, list, 1, 0, false, 3, 5);
        write_synthetic_piece_row(&state, 5, list, 1, 0, true, 4, 6);
        write_synthetic_piece_row(&state, 6, list, 1, 0, false, 5, 0);

        let (chunks, candidates) = state.build_cleanup_chunks(&address, list).unwrap();
        assert_eq!(chunks.len(), 1);
        let runs = &chunks[0].runs;
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].removals, vec![2]);
        assert_eq!(runs[1].removals, vec![5]);
        // The removed rows both reference buffer 1, so it is the sole candidate.
        assert_eq!(candidates, BTreeSet::from([1]));
    }

    /// Two contiguous tombstone runs separated by a *single* live row share that
    /// row as a boundary survivor, so they must be split into separate chunks.
    #[test]
    fn build_cleanup_chunks_splits_runs_sharing_a_survivor() {
        let (state, address) = cleanup_chunk_test_state();
        let list = 1;
        // chain: 1(live) 2(tomb) 3(live) 4(tomb) 5(live)
        write_synthetic_piece_text_parent(&state, &address, list, 1, 5);
        write_synthetic_piece_row(&state, 1, list, 1, 0, false, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 0, true, 1, 3);
        write_synthetic_piece_row(&state, 3, list, 1, 0, false, 2, 4);
        write_synthetic_piece_row(&state, 4, list, 1, 0, true, 3, 5);
        write_synthetic_piece_row(&state, 5, list, 1, 0, false, 4, 0);

        let (chunks, _candidates) = state.build_cleanup_chunks(&address, list).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].runs.len(), 1);
        assert_eq!(chunks[0].runs[0].removals, vec![2]);
        assert_eq!(chunks[1].runs.len(), 1);
        assert_eq!(chunks[1].runs[0].removals, vec![4]);
    }

    /// A fully tombstoned document collapses to one run spanning head..tail.
    #[test]
    fn build_cleanup_chunks_remove_all_collapses_chain() {
        let (state, address) = cleanup_chunk_test_state();
        let list = 1;
        write_synthetic_piece_text_parent(&state, &address, list, 1, 3);
        write_synthetic_piece_row(&state, 1, list, 1, 0, true, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 0, true, 1, 3);
        write_synthetic_piece_row(&state, 3, list, 1, 0, true, 2, 0);

        let (chunks, _candidates) = state.build_cleanup_chunks(&address, list).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].runs.len(), 1);
        assert_eq!(chunks[0].runs[0].removals, vec![1, 2, 3]);
    }

    /// One long contiguous tombstone run that exceeds the per-chunk removal cap
    /// is split across two chunks; the first run names the next tombstone as its
    /// boundary survivor and the remainder relinks against the same live prev.
    #[test]
    fn build_cleanup_chunks_splits_long_run_by_removal_cap() {
        let (state, address) = cleanup_chunk_test_state();
        let list = 1;
        // row 1 is a live head; rows 2..=261 are 260 contiguous tombstones.
        let last_tomb = 1 + MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS as i64 + 4; // 261
        write_synthetic_piece_text_parent(&state, &address, list, 1, last_tomb);
        write_synthetic_piece_row(&state, 1, list, 1, 0, false, 0, 2);
        for id in 2..=last_tomb {
            let next = if id == last_tomb { 0 } else { id + 1 };
            write_synthetic_piece_row(&state, id, list, 1, 0, true, id - 1, next);
        }

        let (chunks, _candidates) = state.build_cleanup_chunks(&address, list).unwrap();
        assert_eq!(chunks.len(), 2);

        let first = &chunks[0].runs;
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].removals.len(),
            MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS
        );
        assert_eq!(first[0].removals[0], 2);
        assert_eq!(*first[0].removals.last().unwrap(), 257);

        let second = &chunks[1].runs;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].removals, vec![258, 259, 260, 261]);

        // Every tombstone is covered exactly once across the chunks.
        let total: usize = chunks
            .iter()
            .flat_map(|c| c.runs.iter())
            .map(|r| r.removals.len())
            .sum();
        assert_eq!(total, 260);
    }

    /// The op type carried by a broadcast cleanup change entry.
    fn broadcast_op_type(broadcast: &(ChangelogEntry, ChangeResponse)) -> OpType {
        broadcast.0.message.op_type
    }

    /// True when buffer `buffer_id`'s `_piecetext_buffers` row (and its owner indexes) have
    /// been physically deleted.
    fn buffer_row_deleted(state: &SpaceState, address: &PieceTextAddress, buffer_id: i64) -> bool {
        let contents_gone = state
            .db
            .get_value(&keys::column_key(BUFFERS_TABLE_NAME, buffer_id, "contents"))
            .unwrap()
            .is_none();
        let owner_index_gone = state
            .db
            .get_value(
                &keys::index_key(
                    BUFFERS_TABLE_NAME,
                    "owner_row_id",
                    address.row_id,
                    buffer_id,
                )
                .unwrap(),
            )
            .unwrap()
            .is_none();
        contents_gone && owner_index_gone
    }

    /// Over-threshold cleanup of a fully tombstoned document commits a
    /// piece-cleanup chunk *first*, then a buffer-cleanup chunk for the
    /// now-orphaned buffer — in that order — and physically deletes the buffer.
    #[tokio::test]
    async fn over_threshold_cleanup_emits_pieces_then_buffers() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        let first = 1000;
        let count = i64::from(CLEANUP_THRESHOLD);
        let last = first + count - 1;
        write_synthetic_piece_text_parent(&state, &address, list, first, last);
        write_synthetic_buffer_row(&state, &address, 1, count * 4);
        for i in 0..count {
            let id = first + i;
            let prev = if i == 0 { 0 } else { id - 1 };
            let next = if i == count - 1 { 0 } else { id + 1 };
            write_synthetic_piece_row(&state, id, list, 1, i * 4, true, prev, next);
        }
        let chain_key = (address.clone(), list);
        state.cleanup_state.chains.insert(
            chain_key.clone(),
            ChainCleanup {
                count: CLEANUP_THRESHOLD,
                pending: true,
                pending_buffers: BTreeSet::new(),
            },
        );

        let outcome = state.run_piece_text_cleanup(chain_key.clone()).await;

        assert!(
            outcome.error.is_none(),
            "cleanup failed: {:?}",
            outcome.error
        );
        // One piece chunk (100 tombstones fit the removal cap) then one buffer
        // chunk for the single orphaned buffer.
        assert_eq!(outcome.broadcasts.len(), 2);
        assert_eq!(
            broadcast_op_type(&outcome.broadcasts[0]),
            OpType::PieceTextCleanupPieces,
            "piece cleanup must be broadcast first"
        );
        assert_eq!(
            broadcast_op_type(&outcome.broadcasts[1]),
            OpType::PieceTextCleanupBuffers,
            "buffer cleanup must be broadcast second"
        );
        assert!(
            !state.cleanup_state.chains.contains_key(&chain_key),
            "fully cleaned chain should be evicted"
        );
        assert_eq!(state.count_tombstone_rows_for_list(list).unwrap(), 0);
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_head_key(list))
                .unwrap(),
            Some(0i64.to_be_bytes().to_vec())
        );
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_tail_key(list))
                .unwrap(),
            Some(0i64.to_be_bytes().to_vec())
        );
        assert!(
            buffer_row_deleted(&state, &address, 1),
            "the orphaned buffer must be physically deleted by buffer cleanup"
        );
    }

    /// A tombstone run longer than the removal cap drains across multiple
    /// committed `PieceTextCleanupPieces` chunks — each verified locally, never
    /// scanning the whole list — leaving the single live row correctly relinked.
    #[tokio::test]
    async fn multi_chunk_cleanup_drains_all_tombstones() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        let head_id = 1000;
        let tomb_count = MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS as i64 + 1; // 257 -> 2 chunks
        let last = head_id + tomb_count; // 1257
        write_synthetic_piece_text_parent(&state, &address, list, head_id, last);
        write_synthetic_buffer_row(&state, &address, 1, (tomb_count + 1) * 4);
        // Live head row, then `tomb_count` contiguous tombstones to the tail.
        write_synthetic_piece_row(&state, head_id, list, 1, 0, false, 0, head_id + 1);
        for id in (head_id + 1)..=last {
            let next = if id == last { 0 } else { id + 1 };
            write_synthetic_piece_row(&state, id, list, 1, (id - head_id) * 4, true, id - 1, next);
        }
        let chain_key = (address.clone(), list);
        state.cleanup_state.chains.insert(
            chain_key.clone(),
            ChainCleanup {
                count: u32::try_from(tomb_count).unwrap(),
                pending: true,
                pending_buffers: BTreeSet::new(),
            },
        );

        let outcome = state.run_piece_text_cleanup(chain_key.clone()).await;

        assert!(
            outcome.error.is_none(),
            "cleanup failed: {:?}",
            outcome.error
        );
        // Two piece chunks, and no buffer chunk: buffer 1 is still referenced by
        // the surviving live head row, so it is not orphaned.
        assert_eq!(
            outcome.broadcasts.len(),
            2,
            "257 tombstones need two chunks under the 256 removal cap"
        );
        for broadcast in &outcome.broadcasts {
            assert_eq!(broadcast_op_type(broadcast), OpType::PieceTextCleanupPieces);
        }
        assert!(
            !buffer_row_deleted(&state, &address, 1),
            "a buffer still referenced by a live piece must not be cleaned"
        );
        assert_eq!(state.count_tombstone_rows_for_list(list).unwrap(), 0);
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_head_key(list))
                .unwrap(),
            Some(head_id.to_be_bytes().to_vec())
        );
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_tail_key(list))
                .unwrap(),
            Some(head_id.to_be_bytes().to_vec()),
            "the surviving live row is the new tail"
        );
        assert!(
            !state.cleanup_state.chains.contains_key(&chain_key),
            "fully cleaned chain should be evicted"
        );
    }

    /// After piece cleanup orphans a buffer, the buffer cleanup phase deletes
    /// the now-unused buffer but leaves a buffer that a surviving live piece
    /// still references — covering both "now-unused buffer scheduled" and "used
    /// buffer not scheduled".
    #[tokio::test]
    async fn cleanup_deletes_orphan_buffer_but_keeps_shared_buffer() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        // chain: 1(live, buffer 2) 2(tomb, buffer 1) 3(tomb, buffer 2)
        write_synthetic_piece_text_parent(&state, &address, list, 1, 3);
        write_synthetic_buffer_row(&state, &address, 1, 4);
        write_synthetic_buffer_row(&state, &address, 2, 8);
        write_synthetic_piece_row(&state, 1, list, 2, 0, false, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 0, true, 1, 3);
        write_synthetic_piece_row(&state, 3, list, 2, 4, true, 2, 0);
        let chain_key = (address.clone(), list);
        state.cleanup_state.chains.insert(
            chain_key.clone(),
            ChainCleanup {
                count: CLEANUP_THRESHOLD,
                pending: true,
                pending_buffers: BTreeSet::new(),
            },
        );

        let outcome = state.run_piece_text_cleanup(chain_key.clone()).await;

        assert!(
            outcome.error.is_none(),
            "cleanup failed: {:?}",
            outcome.error
        );
        // One piece chunk, then one buffer chunk removing only the orphan.
        assert_eq!(outcome.broadcasts.len(), 2);
        assert_eq!(
            broadcast_op_type(&outcome.broadcasts[0]),
            OpType::PieceTextCleanupPieces
        );
        assert_eq!(
            broadcast_op_type(&outcome.broadcasts[1]),
            OpType::PieceTextCleanupBuffers
        );
        assert!(
            buffer_row_deleted(&state, &address, 1),
            "buffer 1, orphaned by cleanup, must be deleted"
        );
        assert!(
            !buffer_row_deleted(&state, &address, 2),
            "buffer 2 is still referenced by the surviving live row and must remain"
        );
        assert_eq!(state.count_tombstone_rows_for_list(list).unwrap(), 0);
        // Only the live head row survives, so it is both head and tail.
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_head_key(list))
                .unwrap(),
            Some(1i64.to_be_bytes().to_vec())
        );
        assert_eq!(
            state
                .db
                .get_value(&keys::piece_coords_tail_key(list))
                .unwrap(),
            Some(1i64.to_be_bytes().to_vec())
        );
    }

    /// A buffer-cleanup failure must retain the orphan buffer for a later retry
    /// rather than dropping it (which would leak the buffer). Pass 1 fails to
    /// delete an orphan buffer — its `_piecetext_buffers` owner mismatches the address, so
    /// the verifier rejects it at commit — and records it in `pending_buffers`
    /// while keeping the chain. Pass 2, after the owner is corrected, retries and
    /// deletes it, then drops the now-idle chain.
    #[tokio::test]
    async fn buffer_cleanup_failure_retains_and_retries_orphan() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        // chain: 1(live, buffer 2) 2(tomb, buffer 1) — buffer 1 becomes orphaned.
        write_synthetic_piece_text_parent(&state, &address, list, 1, 2);
        write_synthetic_buffer_row(&state, &address, 2, 4);
        // Buffer 1's `_piecetext_buffers` row has a MISMATCHED owner, so its Phase-2 delete
        // is rejected by the verifier's owner check → buffer cleanup fails.
        let wrong_owner = PieceTextAddress {
            table: address.table.clone(),
            row_id: address.row_id + 999,
            column: address.column.clone(),
        };
        write_synthetic_buffer_row(&state, &wrong_owner, 1, 8);
        write_synthetic_piece_row(&state, 1, list, 2, 0, false, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 0, true, 1, 0);

        let chain_key = (address.clone(), list);
        state.cleanup_state.chains.insert(
            chain_key.clone(),
            ChainCleanup {
                count: CLEANUP_THRESHOLD,
                pending: true,
                pending_buffers: BTreeSet::new(),
            },
        );

        // Pass 1: piece cleanup commits; buffer cleanup fails on the orphan.
        let outcome = state.run_piece_text_cleanup(chain_key.clone()).await;
        assert!(
            outcome.error.is_some(),
            "buffer cleanup should fail on the mismatched-owner buffer"
        );
        assert_eq!(state.count_tombstone_rows_for_list(list).unwrap(), 0);
        assert!(
            !buffer_row_deleted(&state, &address, 1),
            "buffer 1's delete failed, so it must still be present"
        );
        let entry = state
            .cleanup_state
            .chains
            .get(&chain_key)
            .expect("chain retained while orphan buffers are pending");
        assert_eq!(
            entry.pending_buffers,
            BTreeSet::from([1]),
            "the orphan buffer that failed to delete must be retained for retry"
        );

        // Pass 2: correct the owner, then retry. The chain is live via
        // `pending_buffers` even though no tombstones remain.
        write_synthetic_buffer_row(&state, &address, 1, 8);
        let retry = state.run_piece_text_cleanup(chain_key.clone()).await;
        assert!(retry.error.is_none(), "retry failed: {:?}", retry.error);
        assert!(
            buffer_row_deleted(&state, &address, 1),
            "retry must delete the previously-failed orphan buffer"
        );
        assert!(
            !state.cleanup_state.chains.contains_key(&chain_key),
            "chain is dropped once orphan buffers are drained"
        );
    }

    /// A reconciliation that reports zero tombstones must not erase retained
    /// orphan-buffer retry state — otherwise a later `PieceTextEdit` would leak
    /// buffers still awaiting deletion.
    #[tokio::test]
    async fn pending_buffers_survive_zero_tombstone_reconciliation() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;

        // A chain whose tombstones are gone but with an orphan buffer pending.
        let pending_key = (address.clone(), 1);
        state.cleanup_state.chains.insert(
            pending_key.clone(),
            ChainCleanup {
                count: 0,
                pending: true, // already scheduled → no respawn side effects
                pending_buffers: BTreeSet::from([7]),
            },
        );
        state.maybe_schedule_piece_text_cleanup(address.clone(), 1, 0);
        assert_eq!(
            state
                .cleanup_state
                .chains
                .get(&pending_key)
                .expect("chain with pending orphan buffers must survive reconciliation")
                .pending_buffers,
            BTreeSet::from([7]),
        );

        // Control: a chain with no pending buffers IS dropped on zero tombstones.
        let plain_key = (address.clone(), 2);
        state.cleanup_state.chains.insert(
            plain_key.clone(),
            ChainCleanup {
                count: 5,
                pending: false,
                pending_buffers: BTreeSet::new(),
            },
        );
        state.maybe_schedule_piece_text_cleanup(address.clone(), 2, 0);
        assert!(
            !state.cleanup_state.chains.contains_key(&plain_key),
            "a chain with no pending buffers is removed on zero tombstones"
        );
    }

    /// Driving the two phases separately shows the tolerated temporary-orphan
    /// state: after piece cleanup the buffer is unreferenced but still present,
    /// and the buffer cleanup phase then physically deletes it.
    #[tokio::test]
    async fn piece_cleanup_leaves_orphan_buffer_until_buffer_cleanup() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        // Fully tombstoned 3-row document, all referencing buffer 1.
        write_synthetic_piece_text_parent(&state, &address, list, 1, 3);
        write_synthetic_buffer_row(&state, &address, 1, 12);
        write_synthetic_piece_row(&state, 1, list, 1, 0, true, 0, 2);
        write_synthetic_piece_row(&state, 2, list, 1, 4, true, 1, 3);
        write_synthetic_piece_row(&state, 3, list, 1, 8, true, 2, 0);

        // Phase 1: commit only the piece-cleanup chunks.
        let (piece_chunks, candidates) = state.build_cleanup_chunks(&address, list).unwrap();
        assert_eq!(candidates, BTreeSet::from([1]));
        for envelope in &piece_chunks {
            state
                .commit_cleanup_chunk(envelope.changelog_message().unwrap(), &envelope.address)
                .await
                .unwrap();
        }

        // The buffer is now orphaned but still physically present — the tolerated
        // temporary-orphan state before buffer cleanup runs.
        assert_eq!(state.count_tombstone_rows_for_list(list).unwrap(), 0);
        assert!(
            !buffer_row_deleted(&state, &address, 1),
            "buffer must still exist after piece cleanup, before buffer cleanup"
        );
        assert!(
            state.piece_coords_buffer_range_is_empty(1).unwrap(),
            "piece cleanup must have emptied the buffer's index range"
        );

        // Phase 2: build and commit the buffer-cleanup chunk.
        let buffer_chunks = state
            .build_buffer_cleanup_chunks(&address, &candidates)
            .unwrap();
        assert_eq!(buffer_chunks.len(), 1);
        assert_eq!(buffer_chunks[0].buffer_removals, vec![1]);
        for envelope in &buffer_chunks {
            state
                .commit_cleanup_chunk(envelope.changelog_message().unwrap(), &envelope.address)
                .await
                .unwrap();
        }

        assert!(
            buffer_row_deleted(&state, &address, 1),
            "buffer cleanup must delete the orphaned buffer"
        );
    }

    /// A post-edit reconciliation that pushes the tombstone count over the
    /// threshold flips the chain to pending (scheduling a cleanup pass).
    #[tokio::test]
    async fn schedule_reconciles_undercount_to_real_total() {
        let (mut state, address) = cleanup_chunk_test_state();
        state.cleanup_state.auto_cleanup_enabled = true;
        let list = 1;
        let chain_key = (address.clone(), list);
        state.cleanup_state.chains.insert(
            chain_key.clone(),
            ChainCleanup {
                count: 1,
                pending: false,
                pending_buffers: BTreeSet::new(),
            },
        );

        state.maybe_schedule_piece_text_cleanup(address, list, CLEANUP_THRESHOLD);

        let entry = state
            .cleanup_state
            .chains
            .get(&chain_key)
            .expect("cleanup state should be reconciled");
        assert_eq!(entry.count, CLEANUP_THRESHOLD);
        assert!(
            entry.pending,
            "over-threshold reconciled count should schedule"
        );
    }

    /// Both new cleanup op types are server-only; a user submission of either is
    /// rejected by `handle_change`.
    #[tokio::test]
    async fn handle_change_rejects_user_submitted_piece_cleanup() {
        let (mut state, address) = cleanup_chunk_test_state();
        let envelope = PieceTextCleanupPiecesEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address,
            list_number: 1,
            op_id: 1,
            runs: vec![PieceTextCleanupRunV1 {
                removals: vec![1000],
            }],
        };
        let err = submit_user_cleanup(&mut state, envelope.changelog_message().unwrap()).await;
        assert!(
            err.to_string().contains("server cleanup queue"),
            "expected cleanup-specific rejection, got {err}"
        );
    }

    #[tokio::test]
    async fn handle_change_rejects_user_submitted_buffer_cleanup() {
        let (mut state, address) = cleanup_chunk_test_state();
        let envelope = PieceTextCleanupBuffersEnvelopeV1 {
            version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
            address,
            op_id: 1,
            buffer_removals: vec![1],
        };
        let err = submit_user_cleanup(&mut state, envelope.changelog_message().unwrap()).await;
        assert!(
            err.to_string().contains("server cleanup queue"),
            "expected cleanup-specific rejection, got {err}"
        );
    }

    async fn submit_user_cleanup(
        state: &mut SpaceState,
        message: encrypted_spaces_changelog_core::changelog::LogMessage,
    ) -> ServerError {
        let change = Change {
            entry: ChangelogEntry {
                timestamp: ChangelogEntry::get_unix_timestamp(),
                uid: 0,
                parent_change: 0,
                message,
                sig_ref: 0,
                parent_clc: [0u8; 32],
                signature: vec![],
            },
            hashed_values: HashedValues::new(),
        };
        let auth = AuthContext::new(Some(0), state.space_id);
        state.handle_change(&change, &auth).await.unwrap_err()
    }
}
