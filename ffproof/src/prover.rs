use crate::common::FFProof;
use encrypted_spaces_changelog_core::changelog::{
    verify_op_sequence_flat, ChangeLog, ChangeResponse, ChangelogEntry, ChangelogError,
    FastForwardRange, FlatEntryBytes,
};
use encrypted_spaces_changelog_core::ops::dispatch_extract_and_validate;
use encrypted_spaces_changelog_core::{create_trace, encode_pruned_compact, InputStep, TraceStep};
use encrypted_spaces_ffproof_methods::{EXTEND_FF_ELF, EXTEND_FF_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, SessionStats};

fn flatten_entry_bytes(entries: &[ChangelogEntry]) -> (Vec<u32>, Vec<u8>) {
    let mut entry_ends = Vec::with_capacity(entries.len());
    let mut bytes = Vec::new();
    for entry in entries {
        let entry_bytes = entry.as_bytes();
        let end = bytes
            .len()
            .checked_add(entry_bytes.len())
            .expect("entry byte length overflow");
        assert!(u32::try_from(end).is_ok(), "flat entry blob exceeds u32");
        bytes.extend_from_slice(&entry_bytes);
        entry_ends.push(end as u32);
    }
    (entry_ends, bytes)
}

// TODO: make sure errors are handled without panic

/// Apply the write overlay to a range scan result from the snapshot.
///
/// Merges overlay entries that fall within `[start, end)` into `snapshot_results`:
/// - Overlay `Some(value)` → upsert the key
/// - Overlay `None` (deleted) → remove the key
///
/// Returns the merged results sorted by key.
fn apply_overlay_to_range(
    mut snapshot_results: Vec<(Vec<u8>, Vec<u8>)>,
    overlay: &std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    start: &[u8],
    end: Option<&[u8]>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Collect overlay entries in range
    for (key, value) in overlay.range::<Vec<u8>, _>(start.to_vec()..) {
        if let Some(e) = end {
            if key.as_slice() >= e {
                break;
            }
        }
        match value {
            Some(v) => {
                // Upsert: remove any existing snapshot entry for this key, then add
                snapshot_results.retain(|(k, _)| k != key);
                snapshot_results.push((key.clone(), v.clone()));
            }
            None => {
                // Deleted in overlay: remove from results
                snapshot_results.retain(|(k, _)| k != key);
            }
        }
    }
    snapshot_results.sort_by(|(a, _), (b, _)| a.cmp(b));
    snapshot_results
}

/// Extract `InputStep`s from the changelog entries starting at `start_idx`.
///
/// This function runs each op's `extract_and_validate` with a
/// `ProverReader` that resolves reads against the tree snapshot, then emits
/// `InputStep::Read` and `InputStep::Write` entries in the correct order.
/// The resulting steps are fed to `create_trace` which re-resolves them to
/// build the proof.
///
/// A lightweight write overlay (`BTreeMap`) accumulates `Put`/`Delete`
/// writes from earlier ops so that later ops' key reads can see them
/// ("read your own writes").  For example, a `CreateSpaceOp` that
/// inserts a user row will be visible to a subsequent `InsertOp`'s
/// user-existence check in the same batch.  Prefix and range reads
/// fall through to the immutable snapshot only.
/// Note that reads in an op cannot read earlier writes _in the same
/// op_ (see changelog_core/src/ops/mod.rs).  This only enables reads
/// between separate ops.
///
/// # Arguments
/// * `changelog` - The changelog containing the hash chain entries
/// * `_change_responses` - The change responses for the same changelog range
/// * `start_idx` - The starting index (inclusive)
/// * `tree_snapshot` - The merk tree snapshot to resolve reads against
///
/// # Returns
/// * `Ok(Vec<InputStep>)` - The collected input steps from all entries in the range
/// * `Err(String)` - An error message if deserialization or extraction fails
pub fn extract_input_steps(
    changelog: &ChangeLog,
    _change_responses: &[ChangeResponse],
    start_idx: usize,
    tree_snapshot: &merk::Node,
) -> Result<Vec<InputStep>, String> {
    use encrypted_spaces_changelog_core::changelog::ChangelogEntry;
    use encrypted_spaces_changelog_core::ops::{OpContext, ProverReader};
    use ffproof_tracer_shared::{collect_range, prefix_successor, BatchOp, ProvenRead, ReadOp};
    use merk::GetResult;

    let end_idx = changelog.num_changes() as usize;
    let mut input_steps: Vec<InputStep> = Vec::new();

    // Write overlay: accumulates Put/Delete writes from earlier ops so that
    // later ops can read them without cloning or mutating the tree snapshot.
    // Key lookups check the overlay first; prefix/range reads merge overlay
    // entries with snapshot results.
    //
    // Overlay values:
    //   Some(value)  – Put: key exists with this value
    //   None         – Delete: key was removed
    let mut write_overlay: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> =
        std::collections::BTreeMap::new();
    let mut ctx = OpContext::for_change_sequence();

    for i in start_idx..end_idx {
        // Parse the ChangelogEntry to determine op type
        let entry = ChangelogEntry::from_bytes(&changelog.changes[i].as_bytes())
            .map_err(|e| format!("Failed to parse changelog entry {i}: {e:?}"))?;

        // Build a resolver that checks the write overlay first, then the snapshot.
        let resolver = |op: &ReadOp| -> Result<ProvenRead, ChangelogError> {
            let proven = match op {
                ReadOp::Key(key) => {
                    // Check overlay first
                    let results = if let Some(entry) = write_overlay.get(key.as_slice()) {
                        match entry {
                            Some(value) => vec![(key.clone(), value.clone())],
                            None => vec![], // deleted
                        }
                    } else {
                        // Fall through to snapshot
                        let result = tree_snapshot.get_value(key).map_err(|e| {
                            ChangelogError::Generic(format!(
                                "Tree read failed for key {}: {e:?}",
                                hex::encode(key)
                            ))
                        })?;
                        match result {
                            GetResult::Found(value) => vec![(key.clone(), value)],
                            GetResult::NotFound => vec![],
                            GetResult::Pruned => {
                                return Err(ChangelogError::Generic(format!(
                                    "Pruned node encountered for key {}",
                                    hex::encode(key)
                                )));
                            }
                        }
                    };
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
                ReadOp::Prefix(prefix) => {
                    let end = prefix_successor(prefix);
                    let results = apply_overlay_to_range(
                        collect_range(tree_snapshot, prefix, end.as_deref()),
                        &write_overlay,
                        prefix,
                        end.as_deref(),
                    );
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
                ReadOp::Range { start, end } => {
                    let results = apply_overlay_to_range(
                        collect_range(tree_snapshot, start, Some(end.as_slice())),
                        &write_overlay,
                        start,
                        Some(end.as_slice()),
                    );
                    ProvenRead {
                        op: op.clone(),
                        results,
                    }
                }
            };
            Ok(proven)
        };

        ctx.begin_change(i + 1);

        // Run extract_and_validate with a ProverReader backed by real tree data.
        let mut reader = ProverReader::new(resolver);
        let op_result = dispatch_extract_and_validate(&entry, &mut reader, &ctx)
            .map_err(|e| format!("Op validation failed at entry {i}: {e}"))?;

        // Emit reads first (discovered by the ProverReader), then writes
        for read_op in reader.logged_reads {
            input_steps.push(InputStep::Read(vec![read_op]));
        }

        for write_step in op_result.write_steps {
            match write_step {
                TraceStep::Write(ops) => {
                    // Add Put/Delete writes to the overlay for future ops to read.
                    let mut resolved_ops = Vec::with_capacity(ops.len());
                    for op in &ops {
                        match op {
                            BatchOp::Put { key, value } => {
                                write_overlay.insert(key.clone(), Some(value.clone()));
                                resolved_ops.push(op.clone());
                            }
                            BatchOp::Delete { key } => {
                                write_overlay.insert(key.clone(), None);
                                resolved_ops.push(op.clone());
                            }
                        }
                    }
                    input_steps.push(InputStep::Write(resolved_ops));
                }
                other => {
                    return Err(format!(
                        "Op at entry {i} returned a non-Write step in write_steps: {other:?}"
                    ));
                }
            }
        }
        ctx.finish_change(entry.message.op_type);
    }

    Ok(input_steps)
}

/// Generate a FF proof for changes starting at `start_idx` in the changelog.
/// The changelog and responses are sliced internally to only include the needed data.
#[cfg(test)]
fn prove_ff(
    previous_proof: Option<&FFProof>,
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    start_idx: usize,
    pruned_tree_bytes: Vec<u8>,
) -> (FFProof, SessionStats) {
    prove_ff_chunk(
        previous_proof,
        changelog,
        change_responses,
        start_idx,
        pruned_tree_bytes,
    )
}

pub fn prove_ff_chunk(
    previous_proof: Option<&FFProof>,
    changelog: &ChangeLog,
    change_responses: &[ChangeResponse],
    start_idx: usize,
    // Compact witness bytes from `encode_pruned_compact`.
    pruned_tree_bytes: Vec<u8>,
) -> (FFProof, SessionStats) {
    crate::ensure_risc0_proof_mode();
    let is_first = previous_proof.is_none();

    // Slice the changelog and responses to only include what we need for this proof
    let tail_changelog = changelog.get_tail(start_idx);
    let tail_responses = change_responses[start_idx..].to_vec();

    log::info!(
        "proof_ff: proving {} changes (from {} to {})",
        tail_changelog.num_changes(),
        start_idx,
        changelog.num_changes()
    );

    let end_idx = tail_changelog.num_changes() as usize;
    // The start head is the head after `start_idx` real changes. For the
    // very first chunk this is the post-`initialize` head; for subsequent
    // chunks the previous proof already carries it as `io.end_clc_state`,
    // which is also the only historical head the changelog cache retains
    // (see `ChangeLog::proven_clc_state`). The end head after
    // `start_idx + end_idx` real changes is always the live writer tree.
    let start_clc_state = match previous_proof {
        Some(p) => p.io.end_clc_state.clone(),
        None => {
            assert_eq!(start_idx, 0, "first FF chunk must start at change_id 0");
            changelog.initial_clc_state()
        }
    };
    let end_clc_state = changelog.current_clc_state();
    let start_dc = tail_responses[0].old_root;
    let end_dc = tail_responses[end_idx - 1].new_root;

    // Serialize entry bytes as a flat blob with cumulative offsets
    let (entry_ends, entries_flat) = flatten_entry_bytes(&tail_changelog.changes);

    // Build the FastForwardRange on the host (eliminates need to send responses to guest)
    let range = FastForwardRange {
        end_change_id: end_idx as u32,
        start_clc_state,
        end_clc_state,
        start_dc: start_dc.into(),
        end_dc: end_dc.into(),
        sigref_map: std::collections::BTreeMap::new(), // guest computes the actual map
        recent_roots: Vec::new(),                      // guest seeds/threads the window
        timestamp_hwm: 0,
    };

    if let Some(previous_proof) = previous_proof {
        assert_eq!(
            start_idx as u32, previous_proof.io.end_change_id,
            "extension start index must match the previous proof's ending change id"
        );
        // `range.start_clc_state` == `previous_proof.io.end_clc_state` by
        // construction above; no extra check needed.
        assert_eq!(
            range.start_dc, previous_proof.io.end_dc,
            "extension DC must start from the previous proof's ending DC"
        );
    }

    let range_bytes = postcard::to_allocvec(&range).expect("Failed to serialize range");

    log::debug!(
        "Guest input sizes: entries_flat={}, entry_ends={}, range={}, pruned_tree={}",
        entries_flat.len(),
        entry_ends.len(),
        range_bytes.len(),
        pruned_tree_bytes.len(),
    );

    // Helper: write the flat entry blob + offsets into the env builder.
    // Order: entry_count, entries_byte_len, entry_ends slice, entries_flat slice.
    macro_rules! write_flat_entries {
        ($builder:expr) => {
            $builder
                .write(&entry_ends.len())
                .expect("write entry_count failed")
                .write(&entries_flat.len())
                .expect("write entries_byte_len failed")
                .write_slice(&entry_ends)
                .write_slice(&entries_flat)
        };
    }

    // Create the first proof separately since the inputs/logic is a little different
    let env = if is_first {
        log::info!("Creating the first proof for the changelog (start_idx = {start_idx})");
        debug_assert!({
            let mut dbg_sigref_map = std::collections::BTreeMap::new();
            let mut dbg_recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
            let mut dbg_timestamp_hwm = 0;
            let flat = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
            verify_op_sequence_flat(
                flat,
                &range,
                &pruned_tree_bytes,
                0,
                &mut dbg_sigref_map,
                &mut dbg_recent_roots,
                &mut dbg_timestamp_hwm,
            )
        });

        let mut builder = ExecutorEnv::builder();
        builder.write(&is_first).expect("write is_first failed");
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&pruned_tree_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&pruned_tree_bytes);

        builder.build().unwrap()
    } else {
        log::info!("Extending the fast-forward proof with more changes");

        let previous_receipt = &previous_proof.unwrap().receipt;
        let previous_io = &previous_proof.unwrap().io;
        let previous_io_bytes = previous_io.as_bytes();

        let mut builder = ExecutorEnv::builder();
        builder
            .write(&is_first)
            .expect("write is_first failed")
            .write(&previous_io_bytes.len())
            .expect("write_previous_io_bytes.len() failed")
            .write_slice(&previous_io_bytes)
            .write_slice(&EXTEND_FF_ID)
            .add_assumption(previous_receipt.clone());
        write_flat_entries!(builder);
        builder
            .write(&range_bytes.len())
            .expect("write range_bytes.len() failed")
            .write_slice(&range_bytes)
            .write(&pruned_tree_bytes.len())
            .expect("write pruned tree len failed")
            .write_slice(&pruned_tree_bytes);

        builder.build().unwrap()
    };

    let prover = default_prover();
    log::info!("Calling EXTEND_FF prover");
    // Produce a receipt by proving the specified ELF binary.
    //
    // Use succinct opts so the prover internally collapses the
    // (composite) per-segment receipts into a single recursive
    // `SuccinctReceipt`. Without this the on-wire FF proof is a
    // `CompositeReceipt` whose size grows linearly with the number of
    // segments.
    #[cfg(debug_assertions)]
    let start_time = std::time::Instant::now();
    let proof_info = prover
        .prove_with_opts(env, EXTEND_FF_ELF, &ProverOpts::succinct())
        .unwrap();
    let receipt = proof_info.receipt;
    let stats = proof_info.stats;

    #[cfg(debug_assertions)]
    {
        let prove_duration = start_time.elapsed();
        log::debug!("Elf size: {}", EXTEND_FF_ELF.len());
        log::info!("Proving took: {prove_duration:?}");
        log::debug!("receipt size: {}", receipt.seal_size());
        log::info!(
            "user cycles: {}, paging cycles: {}, sum: {}",
            stats.user_cycles,
            stats.paging_cycles,
            stats.user_cycles + stats.paging_cycles
        );
        log::info!(
            "segments: {}, total cycles: {}, reserved/wasted cycles: {}",
            stats.segments,
            stats.total_cycles,
            stats.reserved_cycles
        );
    }

    assert!(
        receipt.verify(EXTEND_FF_ID).is_ok(),
        "receipt verification failed"
    );

    // Decode journal directly as FastForwardRange - no conversions needed
    let io: FastForwardRange = receipt.journal.decode().unwrap();

    log::info!(
        "Batch proven: {} changes (change ids 0 to {})",
        io.end_change_id,
        io.end_change_id
    );
    log::debug!(
        "start tree head root: {:?}",
        hex::encode::<[u8; 32]>(io.start_clc_state.root.into())
    );
    log::debug!(
        "end tree head root  : {:?}",
        hex::encode::<[u8; 32]>(io.end_clc_state.root.into())
    );
    log::debug!("start DC : {:?}", hex::encode(io.start_dc.as_bytes()));
    log::debug!("end DC   : {:?}", hex::encode(io.end_dc.as_bytes()));

    (FFProof { io, receipt }, stats)
}

/// Generate a FF proof for unproven changes in the changelog and update its state.
/// Note: This doesn't implement any batch size, it will generate a new FF proof if there
/// is one or more unproven changes.
///
/// This is the main entry point for proving. It:
/// 1. Generates a proof covering changes from `proven_up_to` to the end
/// 2. Updates the changelog's `ff_proof` and `proven_up_to` fields
///
/// # Arguments
/// * `changelog` - The changelog to prove (will be mutated to store the proof)
/// * `change_responses` - The change responses corresponding to the changelog entries
/// * `previous_proof` - The previous FF proof if extending an existing proof chain
///
/// # Returns
/// * `true` if proving succeeded or there was nothing to prove
/// * `false` if proving failed
pub fn update_changelog_proof(
    changelog: &mut ChangeLog,
    change_responses: &[ChangeResponse],
    previous_proof: Option<&FFProof>,
    tree_snapshot: &merk::Node,
) -> Result<(), String> {
    let start_idx = changelog.proven_up_to;

    if start_idx >= changelog.num_changes() as usize {
        // Nothing to prove
        return Ok(());
    }

    let steps = match extract_input_steps(changelog, change_responses, start_idx, tree_snapshot) {
        Ok(result) => result,
        Err(e) => return Err(format!("failed to extract input steps: {e}")),
    };

    let tracer_proof = create_trace(tree_snapshot, &steps);
    let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
    let (proof, _stats) = prove_ff_chunk(
        previous_proof,
        changelog,
        change_responses,
        start_idx,
        pruned_tree_bytes,
    );
    let new_proven_up_to = changelog.num_changes() as usize;

    changelog.set_ff_proof(proof.serialize(), new_proven_up_to);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::verify_ff_internal;
    use encrypted_spaces_changelog_test_utils::{TestServer, TEST_CLIENT_UID};
    use serial_test::serial;
    use temp_env;

    /// Extract input steps from a fully-applied server history, build the
    /// pruned-tree trace, and assert the FF-core flat verifier (the same routine
    /// the RISC0 guest runs) accepts the whole range. Returns the steps so
    /// callers can inspect read/write shape. Runs natively — no zkVM, no
    /// `RISC0_DEV_MODE` — so it exercises the real proof path, not a fake.
    fn verify_extracted_ff_core(server: &TestServer) -> Vec<InputStep> {
        let start_idx = 0usize;
        let tree_snapshot = server.tree_snapshot().expect("tree snapshot");
        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            start_idx,
            tree_snapshot,
        )
        .expect("extract_input_steps");
        let tracer_proof = create_trace(tree_snapshot, &steps);
        let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);

        let tail = server.changelog().get_tail(start_idx);
        let entries: Vec<Vec<u8>> = tail.changes.iter().map(|e| e.as_bytes()).collect();
        let end_idx = entries.len();
        let responses = server.responses();
        let range = FastForwardRange {
            end_change_id: end_idx as u32,
            start_clc_state: server.changelog().initial_clc_state(),
            end_clc_state: server.changelog().current_clc_state(),
            start_dc: responses[start_idx].old_root.into(),
            end_dc: responses[start_idx + end_idx - 1].new_root.into(),
            sigref_map: std::collections::BTreeMap::new(),
            recent_roots: Vec::new(),
            timestamp_hwm: 0,
        };

        let (entry_ends, entries_flat) = flatten_entry_bytes(&tail.changes);
        let flat_entries = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
        let mut sigref_map = std::collections::BTreeMap::new();
        let mut recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
        let mut timestamp_hwm = 0;
        assert!(
            verify_op_sequence_flat(
                flat_entries,
                &range,
                &pruned_tree_bytes,
                start_idx as u32,
                &mut sigref_map,
                &mut recent_roots,
                &mut timestamp_hwm,
            ),
            "extracted FF core verification failed"
        );
        steps
    }

    /// A mixed history (table insert + generic list append + two PieceTextEdit
    /// appends) must extract to a self-consistent FF core that verifies.
    #[tokio::test]
    async fn test_ff_core_verifies_mixed_table_list_piece_text_history() {
        let server = TestServer::new_mixed_table_list_piece_text_history().await;
        let op_types: Vec<_> = server
            .changelog()
            .changes
            .iter()
            .map(|entry| entry.message.op_type)
            .collect();
        assert!(op_types.contains(&encrypted_spaces_changelog_core::changelog::OpType::Insert));
        assert!(op_types.contains(&encrypted_spaces_changelog_core::changelog::OpType::ListAppend));
        assert!(
            op_types
                .iter()
                .filter(|op| {
                    **op == encrypted_spaces_changelog_core::changelog::OpType::PieceTextEdit
                })
                .count()
                >= 2,
            "fixture must contain at least two PieceTextEdit changes"
        );

        verify_extracted_ff_core(&server);
    }

    /// Per-change cleanup proof-size budget (mirrors the server's
    /// `CLEANUP_UPDATE_PROOF_BUDGET_BYTES`). Each cleanup op's pruned-tree update
    /// proof must land under this so the system cleanup queue stays cheap.
    const CLEANUP_UPDATE_PROOF_BUDGET_BYTES: usize = 128 * 1024;

    /// A mixed history that drives both split cleanup ops — a signed
    /// `PieceTextEdit` flow followed by a system-source `PieceTextCleanupPieces`
    /// and a system-source `PieceTextCleanupBuffers` — must verify end to end in
    /// the FF core (the same routine the RISC0 guest runs), and each cleanup op's
    /// per-change update proof must stay within the cleanup budget.
    #[tokio::test]
    async fn test_piece_text_cleanup_native_prover_dispatches_and_bounds_proof() {
        use encrypted_spaces_changelog_core::changelog::OpType;

        let server = TestServer::new_piece_text_cleanup_history().await;
        let op_types: Vec<_> = server
            .changelog()
            .changes
            .iter()
            .map(|entry| entry.message.op_type)
            .collect();

        // The fixture must exercise the full split-cleanup shape.
        assert!(
            op_types.contains(&OpType::PieceTextEdit),
            "fixture must contain a PieceTextEdit change"
        );
        let pieces_idx = op_types
            .iter()
            .position(|op| *op == OpType::PieceTextCleanupPieces)
            .expect("fixture must contain a PieceTextCleanupPieces change");
        let buffers_idx = op_types
            .iter()
            .position(|op| *op == OpType::PieceTextCleanupBuffers)
            .expect("fixture must contain a PieceTextCleanupBuffers change");

        // The whole mixed history verifies through the FF core.
        verify_extracted_ff_core(&server);

        // Each cleanup op's per-change update proof stays within budget.
        for (label, idx) in [
            ("PieceTextCleanupPieces", pieces_idx),
            ("PieceTextCleanupBuffers", buffers_idx),
        ] {
            let proof_bytes = server.responses()[idx].pruned_merkle_tree.len();
            assert!(
                proof_bytes < CLEANUP_UPDATE_PROOF_BUDGET_BYTES,
                "{label} update proof is too large: {proof_bytes} bytes \
                 (budget {CLEANUP_UPDATE_PROOF_BUDGET_BYTES})"
            );
        }
    }

    /// Stress/perf gate: optimized piece cleanup must visit far fewer
    /// `_piecetext_pieces` rows than the legacy combined op, which re-read the whole
    /// shrinking list on every chunk.
    ///
    /// Legacy worst case for a fully-tombstoned `MAX_PIECETEXT_PIECES_PER_DOCUMENT`
    /// document, drained in `MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS`-sized chunks,
    /// is `16,384 + 16,128 + ... + 256 = 532,480` row visits (see
    /// PLAN_CLEANUP_OPTIMIZE "Current Behavior"). The split op instead reads each
    /// removed row once — and no boundary survivor (those are derived from the
    /// removed rows' prev_id/next_id, not read) — so total row visits are linear
    /// in the document size.
    #[tokio::test]
    async fn test_piece_text_cleanup_pieces_worst_case_below_legacy_visits() {
        use encrypted_spaces_changelog_core::piece_text::MAX_PIECETEXT_PIECES_PER_DOCUMENT;
        use encrypted_spaces_changelog_core::piece_text_cleanup::MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS;
        use encrypted_spaces_storage_encoding::keys::{parse_key, ParsedKey, PIECE_COORDS_TABLE};

        let doc_rows = MAX_PIECETEXT_PIECES_PER_DOCUMENT;
        let chunk = MAX_PIECE_TEXT_CLEANUP_PIECE_REMOVALS;

        // Legacy whole-list-per-chunk visit count for this worst case.
        let num_chunks = doc_rows.div_ceil(chunk);
        let legacy_visits: usize = (0..num_chunks).map(|k| doc_rows - chunk * k).sum();
        assert_eq!(
            legacy_visits, 532_480,
            "legacy worst-case visit count should match the plan's 532,480 figure"
        );

        let server = TestServer::new_piece_text_cleanup_pieces_stress_history(doc_rows).await;

        // Replay the cleanup history and count distinct `_piecetext_pieces` row reads.
        // `read_piece_coords_row` reads each row's `list_number` column exactly
        // once, so counting those Key reads counts row visits directly.
        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            0,
            server.tree_snapshot().expect("tree snapshot"),
        )
        .expect("extract_input_steps");

        let mut optimized_visits = 0usize;
        for step in &steps {
            if let InputStep::Read(ops) = step {
                for op in ops {
                    if let encrypted_spaces_changelog_core::ReadOp::Key(key) = op {
                        if let Ok(ParsedKey::Column { table, column, .. }) = parse_key(key) {
                            if table == PIECE_COORDS_TABLE && column == "list_number" {
                                optimized_visits += 1;
                            }
                        }
                    }
                }
            }
        }

        // Every tombstoned row is removed exactly once, and no boundary survivor
        // rows are read — the survivors are derived from the removed rows' own
        // prev_id/next_id — so the visit count is exactly `doc_rows`.
        let expected_visits = doc_rows;
        assert_eq!(
            optimized_visits, expected_visits,
            "optimized cleanup should read each removed row exactly once and read \
             no boundary survivor rows"
        );

        // The headline claim: materially below the legacy 532,480-visit shape.
        // Here it is ~32x fewer; require at least a 4x reduction as the gate.
        assert!(
            optimized_visits * 4 < legacy_visits,
            "optimized cleanup row visits {optimized_visits} are not materially below \
             the legacy {legacy_visits}-visit shape"
        );
    }

    // These tests are run with [serial] since each test is multi-core when `--features real-proofs` is used.

    // Proof mode (dev vs real) is handled by ensure_risc0_proof_mode()
    // which is gated on the `real-proofs` feature.

    const TEST_ENV_VARS: [(&str, Option<&str>); 2] = [
        ("RUST_LOG", Some("info")), // Increase the logging output from the RISC0 prover
        ("RISC0_INFO", Some("1")),  // Displays detailed info about prover resource use
    ];

    struct TraceResult {
        pruned_tree_bytes: Vec<u8>,
    }

    fn extract_and_trace(server: &TestServer, start_idx: usize) -> TraceResult {
        let tree_snapshot = server.tree_snapshot().expect("Tree snapshot should exist");
        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            start_idx,
            tree_snapshot,
        )
        .expect("Failed to extract input steps");
        let tracer_proof = create_trace(tree_snapshot, &steps);
        let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);
        TraceResult { pruned_tree_bytes }
    }

    #[tokio::test]
    #[serial]
    async fn test_simple_ff_roundtrip() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_simple_ff_roundtrip: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3;
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            println!("\n=== RISC0 Cycle Report ===");
            println!("User cycles:     {}", stats.user_cycles);
            println!("Paging cycles:   {}", stats.paging_cycles);
            println!("Total cycles:    {}", stats.total_cycles);
            println!("Reserved cycles: {}", stats.reserved_cycles);
            println!("Segments:        {}", stats.segments);
            println!(
                "Cycles per change: {}",
                stats.user_cycles / num_changes as u64
            );
            println!("=========================");

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);

            assert!(res, "Result of verify_ff_internal is false");
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_repeated_ff() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_repeated_ff: RISC0_SKIP_BUILD is set");
            return;
        }
        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let num_changes_per_batch = 3;
            let mut server = TestServer::new_for_tests(num_changes_per_batch, None).await;

            // First batch: create initial proof
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (mut proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            println!(
                "Batch 1: user_cycles={}, total_cycles={}",
                stats.user_cycles, stats.total_cycles
            );
            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Result of verify_ff_internal is false");

            // Update tree snapshot for next batch
            server.update_tree_snapshot();

            let num_additional_batches = 3;
            for i in 0..num_additional_batches {
                println!("\nGenerating FF proof for batch {}", i + 2);

                // Take snapshot before adding more changes
                println!(
                    "Tree snapshot hash before add_more_changes: {:?}",
                    server.tree_snapshot().map(|t| hex::encode(t.hash()))
                );

                server.add_more_changes(num_changes_per_batch).await;

                // Start where the previous proof ended
                let start_idx = proof.io.end_change_id as usize;
                println!(
                    "start_idx = {}, total changes = {}",
                    start_idx,
                    server.changelog().num_changes()
                );

                let tree_snapshot = server.tree_snapshot().expect("Tree snapshot should exist");
                println!(
                    "Using tree snapshot with hash: {}",
                    hex::encode(tree_snapshot.hash())
                );

                let tr = extract_and_trace(&server, start_idx);
                println!("Extracted input steps");

                // Check what the responses say the end root should be
                let responses_for_batch = &server.responses()[start_idx..];
                if !responses_for_batch.is_empty() {
                    println!(
                        "First response old_root: {}",
                        hex::encode(responses_for_batch[0].old_root)
                    );
                    println!(
                        "Last response new_root: {}",
                        hex::encode(responses_for_batch.last().unwrap().new_root)
                    );
                }

                let (new_proof, stats) = prove_ff(
                    Some(&proof),
                    server.changelog(),
                    server.responses(),
                    start_idx,
                    tr.pruned_tree_bytes,
                );
                proof = new_proof;
                println!(
                    "Batch {}: user_cycles={}, total_cycles={}",
                    i + 2,
                    stats.user_cycles,
                    stats.total_cycles
                );
                let res = verify_ff_internal(&proof, EXTEND_FF_ID);
                assert!(res, "Result of verify_ff_internal on batch is false");

                // Update tree snapshot for next batch
                server.update_tree_snapshot();
            }
        })
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_ff_serialization_roundtrip() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_ff_serialization_roundtrip: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3; // Use 3 changes to match test_simple_ff_roundtrip
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            // Test serialization
            let serialized_bytes = proof.serialize();

            // Test deserialization (FFProof uses postcard, not bincode)
            let deserialized_proof =
                FFProof::deserialize(&serialized_bytes).expect("Failed to deserialize FFProof");

            // Verify the deserialized proof works the same as the original
            let res = verify_ff_internal(&deserialized_proof, EXTEND_FF_ID);
            assert!(
                res,
                "Result of verify_ff_internal on deserialized proof is false"
            );

            // Verify the IO fields are the same
            assert_eq!(
                proof.io.start_clc_state,
                deserialized_proof.io.start_clc_state
            );
            assert_eq!(proof.io.end_clc_state, deserialized_proof.io.end_clc_state);
            assert_eq!(proof.io.start_dc, deserialized_proof.io.start_dc);
            assert_eq!(proof.io.end_dc, deserialized_proof.io.end_dc);
        });
    }

    /// Helper: run a single-change FF proof with the given value size and return the cycle stats.
    async fn prove_with_value_size(value_size: usize) -> SessionStats {
        let num_changes = 1;
        let server = TestServer::new_for_tests(num_changes, Some(value_size)).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (_proof, stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            println!("\n=== Cycle stats for value_size={value_size} ===");
            println!("User cycles:   {}", stats.user_cycles);
            println!("Total cycles:  {}", stats.total_cycles);
            println!("Paging cycles: {}", stats.paging_cycles);
            println!("================================================");

            stats
        })
    }

    /// Test that proving works for both small and large value sizes.
    #[tokio::test]
    #[serial]
    async fn test_ff_short_values_use_fewer_cycles() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_ff_short_values_use_fewer_cycles: RISC0_SKIP_BUILD is set");
            return;
        }

        let large_value_size = 128; // at String column limit
        let small_value_size = 32;

        let stats_large = prove_with_value_size(large_value_size).await;
        let stats_small = prove_with_value_size(small_value_size).await;

        println!("\n=== Value-size cycle comparison ===");
        println!(
            "Large value ({large_value_size}B): user_cycles={}, total_cycles={}",
            stats_large.user_cycles, stats_large.total_cycles
        );
        println!(
            "Small value ({small_value_size}B): user_cycles={}, total_cycles={}",
            stats_small.user_cycles, stats_small.total_cycles
        );
        println!("===================================");

        // Both should complete successfully (implicitly verified by reaching here).
        assert!(
            stats_large.user_cycles > 0 && stats_small.user_cycles > 0,
            "Both proofs should complete with nonzero cycles"
        );
    }

    /// Test that an unknown user is rejected during proof verification.
    /// Creates a server where the `_users` table is empty (no user row inserted).
    /// The change is rejected at `add_change` time (via `verify_proof_and_validate`)
    /// because the proof's embedded reads show the user doesn't exist.
    #[tokio::test]
    #[serial]
    async fn test_unknown_user_verification_fails() {
        let server = TestServer::new_for_tests_unknown_user(1).await;

        // The change should have been rejected — the changelog should be empty
        // because verify_proof_and_validate catches the unknown user via the
        // VerifierReader (empty reads → op validation fails).
        assert_eq!(
            server.changelog().num_changes(),
            0,
            "Unknown user change should be rejected at add_change time"
        );
    }

    /// Test that the sigref_map is correctly populated after proving a single-user changelog.
    /// The map should contain one entry: uid -> (latest_change_id, entry_hash).
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_single_user() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_single_user: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 3;
        let uid = TEST_CLIENT_UID; // TestServer's default UID
        let server = TestServer::new_for_tests(num_changes, None).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Proof should verify");

            // sigref_map should have exactly one entry: uid -> (num_changes, _hash)
            assert_eq!(
                proof.io.sigref_map.len(),
                1,
                "Should have one user in sigref_map"
            );
            assert_eq!(
                proof.io.sigref_map.get(&uid).map(|&(cid, _)| cid),
                Some(num_changes as u32),
                "Latest change_id for uid {uid} should be {num_changes}"
            );
            assert!(
                proof
                    .io
                    .sigref_map
                    .get(&uid)
                    .map(|&(_, h)| h != [0u8; 32])
                    .unwrap_or(false),
                "sigref entry hash for uid {uid} must be populated by the guest"
            );
        });
    }

    /// Test that the sigref_map correctly tracks multiple interleaved users.
    /// Users A and B alternate changes: A, B, A, B, A — each user's entry
    /// should point to their own latest change_id.
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_multi_user() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_multi_user: RISC0_SKIP_BUILD is set");
            return;
        }
        let num_changes = 5;
        // uids must match the auto-increment sequence of the _users table.
        let user_uids = [1, 2];
        let (server, expected_last_changes) =
            TestServer::new_multi_user(num_changes, &user_uids).await;

        temp_env::with_vars(TEST_ENV_VARS, || {
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );

            let res = verify_ff_internal(&proof, EXTEND_FF_ID);
            assert!(res, "Multi-user proof should verify");

            // sigref_map should have entries for both users
            assert_eq!(
                proof.io.sigref_map.len(),
                2,
                "Should have two users in sigref_map"
            );

            // Verify each user's latest change_id matches expected
            for &uid in &user_uids {
                let expected = expected_last_changes.get(&uid).copied().unwrap();
                let actual = proof.io.sigref_map.get(&uid).map(|&(cid, _)| cid);
                assert_eq!(
                    actual,
                    Some(expected),
                    "uid {uid}: expected sigref_map entry {expected}, got {actual:?}"
                );
            }
        });
    }

    /// Test that the sigref_map carries correctly across proof chunks.
    /// Prove a first batch, then extend with a second batch. The second
    /// chunk must validate sig_refs against entries from the first chunk.
    #[tokio::test]
    #[serial]
    async fn test_sigref_map_carries_across_chunks() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!("Skipping test_sigref_map_carries_across_chunks: RISC0_SKIP_BUILD is set");
            return;
        }
        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let batch_size = 3;
            let mut server = TestServer::new_for_tests(batch_size, None).await;

            // First batch proof
            let start_idx = 0;
            let tr = extract_and_trace(&server, start_idx);

            let (proof, _stats) = prove_ff(
                None,
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&proof, EXTEND_FF_ID),
                "First batch should verify"
            );
            assert_eq!(proof.io.sigref_map.len(), 1, "One user after first batch");

            // Update tree snapshot and add more changes
            server.update_tree_snapshot();
            server.add_more_changes(batch_size).await;

            // Second batch proof (extending from first)
            let start_idx = proof.io.end_change_id as usize;
            let tr = extract_and_trace(&server, start_idx);

            let (proof2, _stats) = prove_ff(
                Some(&proof),
                server.changelog(),
                server.responses(),
                start_idx,
                tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&proof2, EXTEND_FF_ID),
                "Extended proof should verify"
            );

            // sigref_map should still have one user, now pointing to the latest change
            let total_changes = (batch_size * 2) as u32;
            assert_eq!(
                proof2.io.sigref_map.len(),
                1,
                "Still one user after extension"
            );
            assert_eq!(
                proof2
                    .io
                    .sigref_map
                    .get(&TEST_CLIENT_UID)
                    .map(|&(cid, _)| cid),
                Some(total_changes),
                "Latest change_id should be {total_changes} after both batches"
            );
        })
        .await;
    }

    /// Regression test for the extend-FF continuation bug.
    ///
    /// This bypasses `prove_ff` so the host-side pre-checks cannot catch the
    /// mismatch first. The malicious extension attempts to recursively extend a
    /// valid proof with an unrelated changelog segment whose start CLC/DC do not
    /// match the previous proof's end CLC/DC. The guest must reject it.
    #[tokio::test]
    #[serial]
    async fn test_extend_ff_rejects_non_contiguous_guest_input() {
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            eprintln!(
                "Skipping test_extend_ff_rejects_non_contiguous_guest_input: RISC0_SKIP_BUILD is set"
            );
            return;
        }

        temp_env::async_with_vars(TEST_ENV_VARS, async {
            let batch_size = 3;
            let previous_server = TestServer::new_for_tests(batch_size, None).await;

            let previous_tr = extract_and_trace(&previous_server, 0);
            let (previous_proof, _stats) = prove_ff(
                None,
                previous_server.changelog(),
                previous_server.responses(),
                0,
                previous_tr.pruned_tree_bytes,
            );
            assert!(
                verify_ff_internal(&previous_proof, EXTEND_FF_ID),
                "Previous proof should verify"
            );

            // Build an unrelated first segment and feed it to the guest as if it
            // were the next segment after `previous_proof`.
            let unrelated_server = TestServer::new_for_tests(1, None).await;
            let unrelated_start_idx = 0;
            let unrelated_changelog = unrelated_server.changelog().get_tail(unrelated_start_idx);
            let unrelated_responses = unrelated_server.responses()[unrelated_start_idx..].to_vec();
            let unrelated_end_idx = unrelated_changelog.num_changes() as usize;

            let unrelated_tr = extract_and_trace(&unrelated_server, unrelated_start_idx);

            let (entry_ends, entries_flat) = flatten_entry_bytes(&unrelated_changelog.changes);

            let unrelated_start_tree_head = unrelated_server.changelog().initial_clc_state();
            let unrelated_end_tree_head = unrelated_server.changelog().current_clc_state();

            let range = FastForwardRange {
                end_change_id: unrelated_end_idx as u32,
                start_clc_state: unrelated_start_tree_head,
                end_clc_state: unrelated_end_tree_head,
                start_dc: unrelated_responses[0].old_root.into(),
                end_dc: unrelated_responses[unrelated_end_idx - 1].new_root.into(),
                sigref_map: std::collections::BTreeMap::new(),
                recent_roots: Vec::new(),
                timestamp_hwm: 0,
            };
            assert_ne!(
                range.start_clc_state, previous_proof.io.end_clc_state,
                "test setup must use a mismatched tree head boundary"
            );
            assert_ne!(
                range.start_dc, previous_proof.io.end_dc,
                "test setup must use a mismatched DC boundary"
            );

            let range_bytes = postcard::to_allocvec(&range).expect("Failed to serialize range");
            let previous_io_bytes = previous_proof.io.as_bytes();
            let is_first = false;

            let env = ExecutorEnv::builder()
                .write(&is_first)
                .expect("write is_first failed")
                .write(&previous_io_bytes.len())
                .expect("write previous_io_bytes.len() failed")
                .write_slice(&previous_io_bytes)
                .write_slice(&EXTEND_FF_ID)
                .add_assumption(previous_proof.receipt.clone())
                .write(&entry_ends.len())
                .expect("write entry_count failed")
                .write(&entries_flat.len())
                .expect("write entries_byte_len failed")
                .write_slice(&entry_ends)
                .write_slice(&entries_flat)
                .write(&range_bytes.len())
                .expect("write range_bytes.len() failed")
                .write_slice(&range_bytes)
                .write(&unrelated_tr.pruned_tree_bytes.len())
                .expect("write pruned_tree_bytes.len() failed")
                .write_slice(&unrelated_tr.pruned_tree_bytes)
                .build()
                .unwrap();

            let result = default_prover().prove(env, EXTEND_FF_ELF);
            assert!(
                result.is_err(),
                "guest accepted a non-contiguous FF proof extension"
            );
        })
        .await;
    }

    /// Direct regression for the FF guest's `parent_clc` window check
    ///  Builds a real, valid `verify_op_sequence`
    /// flat input set via the test server, confirms the happy path, then
    /// tampers one entry's signed `parent_clc` and asserts the guest
    /// rejects.
    ///
    /// We invoke `verify_op_sequence` directly rather than the zkVM
    /// prover because the function is pure Rust and this lets the test
    /// run without `--features real-proofs`. The same code path runs
    /// inside the RISC0 guest, so a rejection here is a rejection there.
    #[tokio::test]
    #[serial]
    async fn verify_op_sequence_rejects_tampered_parent_clc() {
        // No RISC0_SKIP_BUILD guard: we never start the prover.
        let num_changes = 3usize;
        let server = TestServer::new_for_tests(num_changes, None).await;

        let tree_snapshot = server.tree_snapshot().expect("tree snapshot");
        let start_idx = 0usize;

        let steps = extract_input_steps(
            server.changelog(),
            server.responses(),
            start_idx,
            tree_snapshot,
        )
        .expect("extract_input_steps");
        let tracer_proof = create_trace(tree_snapshot, &steps);
        let pruned_tree_bytes = encode_pruned_compact(&tracer_proof.pruned_tree);

        let tail = server.changelog().get_tail(start_idx);
        let mut entries: Vec<Vec<u8>> = tail.changes.iter().map(|e| e.as_bytes()).collect();
        let end_idx = entries.len();
        let responses = server.responses();
        let range = FastForwardRange {
            end_change_id: end_idx as u32,
            start_clc_state: server.changelog().initial_clc_state(),
            end_clc_state: server.changelog().current_clc_state(),
            start_dc: responses[start_idx].old_root.into(),
            end_dc: responses[start_idx + end_idx - 1].new_root.into(),
            sigref_map: std::collections::BTreeMap::new(),
            recent_roots: Vec::new(),
            timestamp_hwm: 0,
        };

        // Happy path: the unmodified entries verify cleanly.
        let (entry_ends, entries_flat) = flatten_entry_bytes(&tail.changes);
        let flat_entries = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
        let mut sigref_map = std::collections::BTreeMap::new();
        let mut recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
        let mut timestamp_hwm = 0;
        assert!(
            verify_op_sequence_flat(
                flat_entries,
                &range,
                &pruned_tree_bytes,
                start_idx as u32,
                &mut sigref_map,
                &mut recent_roots,
                &mut timestamp_hwm,
            ),
            "untampered entries must pass verify_op_sequence"
        );
        // Window must hold the seed + one root per change (here 1 + num_changes).
        assert_eq!(recent_roots.len(), 1 + num_changes);

        // Tamper: flip a bit in entry[1]'s `parent_clc`. The entry's
        // signature is not re-checked by verify_op_sequence (the FF
        // guest validates signatures via the sigref pipeline in a
        // separate later stage), so this is exactly the malicious-prover
        // scenario the window check is meant to catch.
        let mut tampered = ChangelogEntry::from_bytes(&entries[1]).expect("parse entry");
        tampered.parent_clc[0] ^= 0x01;
        entries[1] = tampered.as_bytes();

        let mut entries_flat = Vec::new();
        let mut entry_ends = Vec::with_capacity(entries.len());
        for entry in &entries {
            let end = entries_flat
                .len()
                .checked_add(entry.len())
                .expect("entry byte length overflow");
            assert!(u32::try_from(end).is_ok(), "flat entry blob exceeds u32");
            entries_flat.extend_from_slice(entry);
            entry_ends.push(end as u32);
        }
        let flat_entries = FlatEntryBytes::new(&entries_flat, &entry_ends).unwrap();
        let mut sigref_map = std::collections::BTreeMap::new();
        let mut recent_roots: Vec<(u32, [u8; 32])> = Vec::new();
        let mut timestamp_hwm = 0;
        assert!(
            !verify_op_sequence_flat(
                flat_entries,
                &range,
                &pruned_tree_bytes,
                start_idx as u32,
                &mut sigref_map,
                &mut recent_roots,
                &mut timestamp_hwm,
            ),
            "tampered parent_clc must be rejected by verify_op_sequence"
        );
    }

    /// Stage 3a — Empty-range absence-proof spike (PLAN_CLEANUP_OPTIMIZE).
    ///
    /// Measures ONLY the empty-`_piecetext_pieces.buffer_id`-range (absence) proof
    /// component of the future `PieceTextCleanupBuffers` op, for a full
    /// buffer-cleanup chunk, in the *post-piece-cleanup* state. It does not build a
    /// verifier op or a server path; it reuses the tracer idiom
    /// (`create_trace` + `encode_pruned_compact`) and the resolver's own
    /// `index_value_prefix` + `prefix_successor` range construction.
    ///
    /// The dominant unknown is the size of the surrounding live
    /// `_piecetext_pieces.buffer_id` index and how sparsely the cleaned buffer ids
    /// fall within it, so the spike sweeps index size × layout rather than
    /// reporting a single point:
    ///
    /// * each absent target buffer id `Bi` is bracketed by **dense adjacent
    ///   neighbor keys** (`Bi-1`, `Bi+1`, ... live), so each absence proof must
    ///   descend to and include real boundary nodes;
    /// * `clustered` tiles the target blocks into one contiguous keyspace region
    ///   (rides shared subtrees — the friendly case);
    /// * `sparse` spreads the 256 blocks by a huge stride across the full
    ///   positive i64 keyspace (disjoint subtrees — the worst case);
    /// * both layouts are run and the **max** is taken.
    ///
    /// `#[ignore]`d so it never runs in the normal sweep. Invoke explicitly:
    ///
    /// ```text
    /// RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 \
    ///   cargo test -p encrypted-spaces-ffproof empty_range_proof_size -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "Stage 3a measurement spike; run explicitly with --ignored --nocapture"]
    fn empty_range_proof_size() {
        use encrypted_spaces_changelog_core::piece_text::MAX_PIECETEXT_PIECES_PER_DOCUMENT;
        use encrypted_spaces_changelog_core::piece_text_cleanup::MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS;
        use encrypted_spaces_changelog_core::piece_text_resolver::PIECE_COORDS_COL_BUFFER_ID;
        use encrypted_spaces_storage_encoding::keys::{
            index_key, index_value_prefix, row_id_to_bytes, PIECE_COORDS_TABLE,
        };
        use ffproof_tracer_shared::{prefix_successor, ReadOp};
        use merk::InMemoryMerk;
        use std::collections::HashSet;

        // The named constant `CLEANUP_UPDATE_PROOF_BUDGET_BYTES` is introduced
        // in a later stage; the spike hard-codes the plan's stated 128 KiB
        // per-change cleanup budget so it can run standalone.
        const CLEANUP_UPDATE_PROOF_BUDGET_BYTES: usize = 128 * 1024;
        const HALF_BUDGET: usize = CLEANUP_UPDATE_PROOF_BUDGET_BYTES / 2;

        // One cleanup chunk's worth of buffers - the unit the proof must cover.
        let n_targets: usize = MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS;

        // Build a `_piecetext_pieces.buffer_id` index merk tree from a sorted set of
        // live buffer ids: one index entry per id, value = its row_id (8 bytes
        // BE), exactly as `piece_text_resolver::index_put` writes it.
        fn build_index_tree(live_ids: &[i64]) -> merk::Node {
            let merk = InMemoryMerk::new();
            for (i, &id) in live_ids.iter().enumerate() {
                let row_id = (i as i64) + 1; // positive, unique
                let key = index_key(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, id, row_id)
                    .expect("index_key");
                merk.put(key, row_id_to_bytes(row_id).to_vec())
                    .expect("merk put");
            }
            merk.snapshot().expect("non-empty index tree")
        }

        // One empty `ReadOp::Range` per absent target, built exactly like
        // `piece_text_resolver` builds its `buffer_id` lookups.
        fn empty_range_reads(targets: &[i64]) -> Vec<ReadOp> {
            targets
                .iter()
                .map(|&bi| {
                    let prefix =
                        index_value_prefix(PIECE_COORDS_TABLE, PIECE_COORDS_COL_BUFFER_ID, bi)
                            .expect("index_value_prefix");
                    let end = prefix_successor(&prefix).expect("prefix has a successor");
                    ReadOp::Range { start: prefix, end }
                })
                .collect()
        }

        // Construct (sorted live ids, absent targets) for a layout. `block_half`
        // is the number of present neighbor ids on each side of every absent
        // target (>= 1 guarantees the immediate `Bi-1`/`Bi+1` brackets are live,
        // forcing each absence proof down to real boundary nodes). Total index
        // size = n_targets * 2 * block_half.
        fn layout(n_targets: usize, block_half: i64, sparse: bool) -> (Vec<i64>, Vec<i64>) {
            let block_w = 2 * block_half + 1; // [Bi-H ..= Bi+H]
            let stride: i64 = if sparse {
                i64::MAX / (n_targets as i64 + 1)
            } else {
                block_w
            };
            let base: i64 = block_half + 1; // keeps the first Bi-block_half >= 1
            let mut live = Vec::with_capacity(n_targets * 2 * block_half as usize);
            let mut targets = Vec::with_capacity(n_targets);
            for i in 0..n_targets as i64 {
                let bi = base + i * stride;
                targets.push(bi);
                for d in 1..=block_half {
                    live.push(bi - d);
                    live.push(bi + d);
                }
            }
            live.sort_unstable();
            (live, targets)
        }

        let measure = |block_half: i64, sparse: bool| -> usize {
            let (live, targets) = layout(n_targets, block_half, sparse);

            // Confirm the construction really is an absence proof bracketed by
            // dense neighbors: every target absent, every immediate neighbor
            // present, all ids positive.
            let live_set: HashSet<i64> = live.iter().copied().collect();
            assert!(live.iter().all(|&x| x > 0), "live ids must be positive");
            assert!(
                targets.iter().all(|&b| !live_set.contains(&b)),
                "every target must be absent from the index"
            );
            assert!(
                targets
                    .iter()
                    .all(|&b| live_set.contains(&(b - 1)) && live_set.contains(&(b + 1))),
                "every target must be bracketed by live Bi-1 / Bi+1 neighbors"
            );

            let tree = build_index_tree(&live);
            let steps = vec![InputStep::Read(empty_range_reads(&targets))];
            let proof = create_trace(&tree, &steps);
            let bytes = encode_pruned_compact(&proof.pruned_tree);
            eprintln!(
                "  block_half={block_half:>3} index_size={:>6} {:<9} \
                 full={:>5} pruned={:>5} -> {:>7} bytes ({:>3} bytes/buffer)",
                live.len(),
                if sparse { "sparse" } else { "clustered" },
                proof.pruned_tree.count_full(),
                proof.pruned_tree.count_pruned(),
                bytes.len(),
                bytes.len() / n_targets,
            );
            bytes.len()
        };

        eprintln!(
            "\n[Stage 3a] empty-range absence-proof size for a {n_targets}-buffer cleanup chunk"
        );
        eprintln!(
            "  budget CLEANUP_UPDATE_PROOF_BUDGET_BYTES = {CLEANUP_UPDATE_PROOF_BUDGET_BYTES} \
             bytes (128 KiB); half = {HALF_BUDGET}\n"
        );

        // Sweep the surrounding-index size (via block_half) for both layouts.
        // The headline block_half keeps the live index at the plan's
        // per-document worst-case scale after the buffer cleanup cap changes.
        assert_eq!(
            MAX_PIECETEXT_PIECES_PER_DOCUMENT, 16_384,
            "headline block_half assumes the documented 16,384 piece cap"
        );
        assert_eq!(
            MAX_PIECETEXT_PIECES_PER_DOCUMENT % (n_targets * 2),
            0,
            "headline block_half assumes the piece cap divides evenly by target brackets"
        );
        let headline_block_half = (MAX_PIECETEXT_PIECES_PER_DOCUMENT / (n_targets * 2)) as i64;
        let mut worst = 0usize;
        let mut worst_at = (0i64, false);
        let mut headline = 0usize;
        for &block_half in &[1i64, 4, 16, 32, 64, 128] {
            for &sparse in &[false, true] {
                let n = measure(block_half, sparse);
                if n > worst {
                    worst = n;
                    worst_at = (block_half, sparse);
                }
                if block_half == headline_block_half && sparse {
                    headline = n; // document-cap index, worst-case layout
                }
            }
        }

        let verdict = |n: usize| -> &'static str {
            if n < HALF_BUDGET {
                "UNDER half-budget"
            } else if n < CLEANUP_UPDATE_PROOF_BUDGET_BYTES {
                "between half and full budget"
            } else {
                "OVER full budget"
            }
        };

        eprintln!(
            "\n  >>> WORST over sweep = {worst} bytes (block_half={}, {}) [{}]",
            worst_at.0,
            if worst_at.1 { "sparse" } else { "clustered" },
            verdict(worst),
        );
        eprintln!(
            "  >>> HEADLINE (16,384-entry index, sparse) = {headline} bytes [{}]",
            verdict(headline),
        );
        eprintln!(
            "  >>> Stage 3a decision: {}\n",
            if headline < HALF_BUDGET {
                "PASS — empty-range component well under half budget; Stage 3b greenlit."
            } else if headline < CLEANUP_UPDATE_PROOF_BUDGET_BYTES {
                "REVIEW — component above half budget; run the binding Stage 3b \
                 full-op measurement and enable only if that stays under budget."
            } else {
                "ESCALATE — empty-range component alone exceeds the full per-change \
                 budget. Do NOT build Stage 3b; use a specialized absence-proof helper \
                 or refcounts (PLAN_CLEANUP_OPTIMIZE 'Why Not Refcounts')."
            }
        );

        // Sanity floor only: the dense-neighbor brackets must have forced a
        // non-trivial descent (a collapsed/empty proof would mean the
        // measurement is broken, not that absence is free).
        assert!(
            headline > n_targets,
            "empty-range absence proof collapsed ({headline} bytes for {n_targets} buffers); \
             the dense-neighbor bracket did not force a real descent — measurement is broken"
        );
    }

    /// Stage 3b - full `PieceTextCleanupBuffers` op proof-size measurement.
    ///
    /// Measures the real verifier path for a full buffer-cleanup chunk:
    /// schema PieceText-column auth, `_piecetext_buffers` owner metadata reads, empty
    /// `_piecetext_pieces.buffer_id` range reads, and derived `_piecetext_buffers` column and
    /// owner-index deletes. The tree layout mirrors the Stage 3a absence spike:
    /// every target buffer id is absent from the piece-coordinate index but
    /// bracketed by dense live neighbor index keys, with both clustered and
    /// sparse target layouts measured.
    /// The reduced buffer-cleanup cap is accepted only if this binding full-op
    /// measurement stays under the 128 KiB per-change cleanup budget.
    ///
    /// `#[ignore]`d so normal test sweeps skip it. Invoke explicitly:
    ///
    /// ```text
    /// RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 \
    ///   cargo test -p encrypted-spaces-ffproof piece_text_cleanup_buffers_full_op_proof_size -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "Stage 3b proof-size measurement; run explicitly with --ignored --nocapture"]
    fn piece_text_cleanup_buffers_full_op_proof_size() {
        use encrypted_spaces_changelog_core::changelog::{
            ChangelogEntry, ChangelogError, LogMessage, OpType, ROOT_TREE_PATH,
        };
        use encrypted_spaces_changelog_core::ops::{
            OpContext, OpVerifier, PieceTextCleanupBuffersOp, ProverReader,
        };
        use encrypted_spaces_changelog_core::piece_text::{
            PieceTextAddress, MAX_PIECETEXT_PIECES_PER_DOCUMENT,
        };
        use encrypted_spaces_changelog_core::piece_text_cleanup::{
            PieceTextCleanupBuffersEnvelopeV1, MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS,
            PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
        };
        use encrypted_spaces_changelog_core::piece_text_resolver::{
            BUFFERS_COL_OWNER_COLUMN, BUFFERS_COL_OWNER_ROW_ID, BUFFERS_COL_OWNER_TABLE,
            PIECE_COORDS_COL_BUFFER_ID,
        };
        use encrypted_spaces_changelog_core::{ReadOp, TraceStep};
        use encrypted_spaces_storage_encoding::keys::{
            column_key, index_key, row_id_to_bytes, schema_piece_text_columns_key, BUFFERS_TABLE,
            PIECE_COORDS_TABLE,
        };
        use encrypted_spaces_storage_encoding::stored_value::StoredValue;
        use merk::{GetResult, InMemoryMerk};
        use std::collections::{BTreeSet, HashSet};

        const CLEANUP_UPDATE_PROOF_BUDGET_BYTES: usize = 128 * 1024;
        const TABLE: &str = "docs";
        const ROW_ID: i64 = 42;
        const COLUMN: &str = "body";
        const OP_ID: i64 = 77;
        const BLOCK_HALF: i64 = 128;

        fn stored_i64(value: i64) -> Vec<u8> {
            postcard::to_allocvec(&StoredValue::I64(value)).expect("stored i64")
        }

        fn stored_string(value: &str) -> Vec<u8> {
            postcard::to_allocvec(&StoredValue::String(value.to_string())).expect("stored string")
        }

        fn layout(n_targets: usize, block_half: i64, sparse: bool) -> (Vec<i64>, Vec<i64>) {
            let block_w = 2 * block_half + 1;
            let stride = if sparse {
                i64::MAX / (n_targets as i64 + 1)
            } else {
                block_w
            };
            let base = block_half + 1;
            let mut live = Vec::with_capacity(n_targets * 2 * block_half as usize);
            let mut targets = Vec::with_capacity(n_targets);
            for i in 0..n_targets as i64 {
                let bi = base + i * stride;
                targets.push(bi);
                for d in 1..=block_half {
                    live.push(bi - d);
                    live.push(bi + d);
                }
            }
            live.sort_unstable();
            (live, targets)
        }

        fn put(merk: &InMemoryMerk, key: Vec<u8>, value: Vec<u8>) {
            merk.put(key, value).expect("merk put");
        }

        fn build_tree(live_buffer_ids: &[i64], target_buffer_ids: &[i64]) -> merk::Node {
            let merk = InMemoryMerk::new();
            let mut piece_text_columns = BTreeSet::new();
            piece_text_columns.insert(COLUMN.to_string());
            put(
                &merk,
                schema_piece_text_columns_key(TABLE),
                encrypted_spaces_storage_encoding::encode_column_names(&piece_text_columns),
            );

            for (i, &buffer_id) in live_buffer_ids.iter().enumerate() {
                let row_id = (i as i64) + 1;
                put(
                    &merk,
                    index_key(
                        PIECE_COORDS_TABLE,
                        PIECE_COORDS_COL_BUFFER_ID,
                        buffer_id,
                        row_id,
                    )
                    .expect("piece coord buffer_id index key"),
                    row_id_to_bytes(row_id).to_vec(),
                );
            }

            for &buffer_id in target_buffer_ids {
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_TABLE),
                    stored_string(TABLE),
                );
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_ROW_ID),
                    stored_i64(ROW_ID),
                );
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, BUFFERS_COL_OWNER_COLUMN),
                    stored_string(COLUMN),
                );
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, "author_id"),
                    stored_i64(7),
                );
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, "len_bytes"),
                    stored_i64(4),
                );
                put(
                    &merk,
                    column_key(BUFFERS_TABLE, buffer_id, "contents"),
                    vec![0xAB; 32],
                );
                for (column, value) in [
                    (
                        BUFFERS_COL_OWNER_COLUMN,
                        encrypted_spaces_storage_encoding::TupleElement::String(COLUMN.to_string()),
                    ),
                    (
                        BUFFERS_COL_OWNER_ROW_ID,
                        encrypted_spaces_storage_encoding::TupleElement::Int(ROW_ID),
                    ),
                    (
                        BUFFERS_COL_OWNER_TABLE,
                        encrypted_spaces_storage_encoding::TupleElement::String(TABLE.to_string()),
                    ),
                ] {
                    put(
                        &merk,
                        index_key(BUFFERS_TABLE, column, value, buffer_id)
                            .expect("buffer owner index key"),
                        row_id_to_bytes(buffer_id).to_vec(),
                    );
                }
            }

            merk.snapshot().expect("cleanup proof tree snapshot")
        }

        fn envelope(targets: &[i64]) -> PieceTextCleanupBuffersEnvelopeV1 {
            PieceTextCleanupBuffersEnvelopeV1 {
                version: PIECE_TEXT_CLEANUP_ENVELOPE_VERSION_V1,
                address: PieceTextAddress {
                    table: TABLE.to_string(),
                    row_id: ROW_ID,
                    column: COLUMN.to_string(),
                },
                op_id: OP_ID,
                buffer_removals: targets.to_vec(),
            }
        }

        fn entry(env: &PieceTextCleanupBuffersEnvelopeV1) -> ChangelogEntry {
            ChangelogEntry {
                timestamp: 1,
                uid: 0,
                parent_change: 0,
                message: LogMessage {
                    op_type: OpType::PieceTextCleanupBuffers,
                    tree_path: ROOT_TREE_PATH.to_vec(),
                    entries: vec![env.changelog_entry_kv().expect("cleanup manifest kv")],
                },
                sig_ref: 0,
                parent_clc: [0u8; 32],
                signature: Vec::new(),
            }
        }

        fn proven_read_from_tree(
            tree: &merk::Node,
            op: &ReadOp,
        ) -> Result<encrypted_spaces_changelog_core::ProvenRead, ChangelogError> {
            let results = match op {
                ReadOp::Key(key) => match tree.get_value(key).map_err(|e| {
                    ChangelogError::Generic(format!(
                        "tree read failed for key {}: {e:?}",
                        hex::encode(key)
                    ))
                })? {
                    GetResult::Found(value) => vec![(key.clone(), value)],
                    GetResult::NotFound => Vec::new(),
                    GetResult::Pruned => {
                        return Err(ChangelogError::Generic(format!(
                            "pruned node encountered for key {}",
                            hex::encode(key)
                        )));
                    }
                },
                ReadOp::Prefix(prefix) => {
                    let end = ffproof_tracer_shared::prefix_successor(prefix);
                    ffproof_tracer_shared::collect_range(tree, prefix, end.as_deref())
                }
                ReadOp::Range { start, end } => {
                    ffproof_tracer_shared::collect_range(tree, start, Some(end.as_slice()))
                }
            };
            Ok(encrypted_spaces_changelog_core::ProvenRead {
                op: op.clone(),
                results,
            })
        }

        fn extract_full_op_steps(tree: &merk::Node, targets: &[i64]) -> Vec<InputStep> {
            let env = envelope(targets);
            let change = entry(&env);
            let ctx = OpContext::for_change_id(OP_ID as usize);
            let mut reader = ProverReader::new(|op| proven_read_from_tree(tree, op));
            let op_result =
                PieceTextCleanupBuffersOp::extract_and_validate(&change, &mut reader, &ctx)
                    .expect("cleanup op measurement");

            let mut steps = Vec::new();
            for read_op in reader.logged_reads {
                steps.push(InputStep::Read(vec![read_op]));
            }
            for write_step in op_result.write_steps {
                match write_step {
                    TraceStep::Write(ops) => steps.push(InputStep::Write(ops)),
                    TraceStep::Read(_) => panic!("op verifier returned a read trace step"),
                }
            }
            steps
        }

        fn measure(sparse: bool) -> usize {
            let n_targets = MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS;
            let (live, targets) = layout(n_targets, BLOCK_HALF, sparse);
            assert_eq!(
                live.len(),
                MAX_PIECETEXT_PIECES_PER_DOCUMENT,
                "full-op proof measurement must keep the surrounding buffer_id index at document-cap scale"
            );
            let live_set: HashSet<i64> = live.iter().copied().collect();
            assert!(live.iter().all(|&x| x > 0), "live ids must be positive");
            assert!(
                targets.iter().all(|&b| !live_set.contains(&b)),
                "target buffers must be absent from _piecetext_pieces.buffer_id"
            );
            assert!(
                targets
                    .iter()
                    .all(|&b| live_set.contains(&(b - 1)) && live_set.contains(&(b + 1))),
                "every target must be bracketed by live Bi-1 / Bi+1 neighbors"
            );

            let tree = build_tree(&live, &targets);
            let steps = extract_full_op_steps(&tree, &targets);
            let write_ops = steps
                .iter()
                .filter_map(|step| match step {
                    InputStep::Write(ops) => Some(ops.len()),
                    InputStep::Read(_) => None,
                })
                .sum::<usize>();
            let read_ops = steps
                .iter()
                .filter_map(|step| match step {
                    InputStep::Read(ops) => Some(ops.len()),
                    InputStep::Write(_) => None,
                })
                .sum::<usize>();
            let proof = create_trace(&tree, &steps);
            let bytes = encode_pruned_compact(&proof.pruned_tree);
            eprintln!(
                "  {:<9} targets={n_targets} index_size={:>6} reads={read_ops:>4} \
                 writes={write_ops:>5} full={:>5} pruned={:>5} -> {:>7} bytes",
                if sparse { "sparse" } else { "clustered" },
                live.len(),
                proof.pruned_tree.count_full(),
                proof.pruned_tree.count_pruned(),
                bytes.len(),
            );
            bytes.len()
        }

        eprintln!(
            "\n[Stage 3b] PieceTextCleanupBuffers full-op proof size for a {}-buffer chunk",
            MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS
        );
        eprintln!(
            "  budget CLEANUP_UPDATE_PROOF_BUDGET_BYTES = {CLEANUP_UPDATE_PROOF_BUDGET_BYTES} bytes (128 KiB)\n"
        );

        let clustered = measure(false);
        let sparse = measure(true);
        let worst = clustered.max(sparse);
        eprintln!("\n  >>> WORST full-op proof = {worst} bytes\n");

        eprintln!(
            "  >>> Stage 3b decision: {}\n",
            if worst < CLEANUP_UPDATE_PROOF_BUDGET_BYTES {
                "PASS - full op is under budget; dispatch can be reconsidered."
            } else {
                "ESCALATE - full op exceeds budget; dispatch must remain disabled."
            }
        );

        assert!(
            worst > MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS,
            "full-op proof collapsed ({worst} bytes for {} buffers); measurement is broken",
            MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS
        );
        assert!(
            worst < CLEANUP_UPDATE_PROOF_BUDGET_BYTES,
            "PieceTextCleanupBuffers full-op proof {worst} bytes exceeds \
             CLEANUP_UPDATE_PROOF_BUDGET_BYTES {CLEANUP_UPDATE_PROOF_BUDGET_BYTES} \
             at cap {MAX_PIECE_TEXT_CLEANUP_BUFFER_REMOVALS}"
        );
    }
}
