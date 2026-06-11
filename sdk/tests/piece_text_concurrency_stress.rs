#![cfg(feature = "local-transport")]

mod piece_text_support;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_changelog_core::{
    piece_text::{
        BufferCoord, PieceTextAddress, PieceTextEditEnvelopeV1, PieceTextEditItemManifest,
    },
    piece_text_planner::{
        plan_edit, BufferMeta, BufferSnapshot, PieceRow, PieceSnapshot, PlannerInput,
    },
};
use encrypted_spaces_sdk::{local_transport::LocalTransport, PieceTextArea};
use piece_text_support::{
    create_two_client_piece_text_fixture, server_changelog_len, COL, LIST_NUMBER, TABLE,
};
use rand::{rngs::SmallRng, Rng, SeedableRng, TryRngCore};
use tokio::{sync::Mutex, time::sleep};

#[derive(Debug, Clone)]
enum AcceptedKind {
    Insert,
    Delete,
    SameCoordInsert,
}

#[derive(Debug, Clone)]
struct AcceptedEdit {
    envelope: PieceTextEditEnvelopeV1,
    canonical_bytes: Vec<u8>,
    inserted_texts: Vec<String>,
    kind: AcceptedKind,
}

#[derive(Debug, Default)]
struct AcceptedLog {
    next_change_index: usize,
    records: Vec<AcceptedEdit>,
}

struct SharedStress {
    transport: LocalTransport,
    submit_gate: Mutex<()>,
    log: Mutex<AcceptedLog>,
    protected_chars: AtomicU64,
    payload_seq: AtomicU64,
    /// Total `PieceTextCleanup{Pieces,Buffers}` ops the drivers have forced.
    cleanup_ops: AtomicU64,
    /// The document the drivers edit / clean up.
    address: PieceTextAddress,
}

/// Fuzz the full PieceText surface: two clients make concurrent random edits
/// while each occasionally forces a server-side cleanup pass
/// (`PieceTextCleanupPieces` + `PieceTextCleanupBuffers`) interleaved with the
/// edits. Verifies the system ops never corrupt the document:
///   - after the run both clients **converge** to the same snapshot, which equals
///     the edit-only offline fold (so cleanup, which only removes tombstones, was
///     render-preserving throughout);
///   - same-coordinate inserts keep their LIFO-protected prefix;
///   - every forced cleanup passes `assert_piece_text_invariants` (well-formed
///     `_piecetext_pieces` chain; every live piece's buffer exists and fits), checked
///     before and after each pass and once more on the final server state.
///
/// `FUZZ_ITERS` = per-driver edit count (default 200), seed via `FUZZ_SEED`. Run:
///   cargo test -p encrypted-spaces-sdk --test piece_text_concurrency_stress \
///     fuzz_piecetext -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn fuzz_piecetext() -> Result<()> {
    let seed = stress_seed();
    println!("FUZZ_SEED={seed}");

    // Per-driver iteration count.
    let iters: usize = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let fixture = create_two_client_piece_text_fixture().await?;
    let start_index = server_changelog_len(&fixture.transport).await;
    let alice_area = fixture.alice.piece_text(TABLE, fixture.row_id, COL);
    let bob_area = fixture.bob.piece_text(TABLE, fixture.row_id, COL);

    let shared = Arc::new(SharedStress {
        transport: fixture.transport.clone(),
        submit_gate: Mutex::new(()),
        log: Mutex::new(AcceptedLog {
            next_change_index: start_index,
            records: Vec::new(),
        }),
        protected_chars: AtomicU64::new(0),
        payload_seq: AtomicU64::new(0),
        cleanup_ops: AtomicU64::new(0),
        address: PieceTextAddress {
            table: TABLE.to_string(),
            row_id: fixture.row_id,
            column: COL.to_string(),
        },
    });

    let alice_driver = tokio::spawn(driver_loop(
        "alice",
        alice_area,
        Arc::clone(&shared),
        seed ^ 0xA11C_E5EED,
        iters,
    ));
    let bob_driver = tokio::spawn(driver_loop(
        "bob",
        bob_area,
        Arc::clone(&shared),
        seed ^ 0xB0B5_E5EED,
        iters,
    ));

    alice_driver.await.unwrap()?;
    bob_driver.await.unwrap()?;

    let alice_area = fixture.alice.piece_text(TABLE, fixture.row_id, COL);
    let bob_area = fixture.bob.piece_text(TABLE, fixture.row_id, COL);
    let (alice_snapshot, bob_snapshot) = sync_until_quiescent(&alice_area, &bob_area).await?;
    assert_eq!(alice_snapshot, bob_snapshot);

    let accepted = {
        let log = shared.log.lock().await;
        log.records.clone()
    };
    assert!(
        !accepted.is_empty(),
        "stress run must accept at least one piece-text edit",
    );

    let server_envelopes = accepted_envelopes_since(&shared.transport, start_index).await?;
    assert_eq!(
        server_envelopes.len(),
        accepted.len(),
        "accepted server entries and submitted-success log diverged",
    );

    let offline = replay_with_actual_planner(&accepted)?;
    assert_eq!(alice_snapshot, offline.snapshot);
    assert_eq!(bob_snapshot, offline.snapshot);

    let submitted_ids: HashSet<[u8; 16]> = accepted
        .iter()
        .map(|record| record.envelope.op_id)
        .collect();
    assert_eq!(submitted_ids.len(), accepted.len());
    assert_eq!(submitted_ids, offline.op_ids);

    let canonical_bytes: HashSet<Vec<u8>> = accepted
        .iter()
        .map(|record| record.canonical_bytes.clone())
        .collect();
    assert_eq!(
        canonical_bytes.len(),
        accepted.len(),
        "accepted canonical envelope bytes must be logged once per edit",
    );

    assert_lifo_protected_prefix(&accepted, &alice_snapshot);

    // The interleaved cleanup must have left the server structurally sound, and
    // must actually have run (else this isn't testing system ops at all).
    {
        let state = shared.transport.state_for_tests().await;
        state
            .assert_piece_text_invariants(&shared.address)
            .unwrap_or_else(|e| panic!("final piece-text invariants violated (seed {seed}): {e}"));
    }
    let cleanup_ops = shared.cleanup_ops.load(Ordering::SeqCst);
    assert!(
        cleanup_ops > 0,
        "fuzz never exercised cleanup (seed {seed}); edits aren't producing tombstones",
    );
    println!("fuzz_piecetext seed {seed}: {cleanup_ops} cleanup ops committed");
    Ok(())
}

#[tokio::test]
async fn offline_renderer_agrees_with_sdk_snapshot_for_astral_text() -> Result<()> {
    let fixture = create_two_client_piece_text_fixture().await?;
    let start_index = server_changelog_len(&fixture.transport).await;
    let area = fixture.alice.piece_text(TABLE, fixture.row_id, COL);
    let shared = Arc::new(SharedStress {
        transport: fixture.transport.clone(),
        submit_gate: Mutex::new(()),
        log: Mutex::new(AcceptedLog {
            next_change_index: start_index,
            records: Vec::new(),
        }),
        protected_chars: AtomicU64::new(0),
        payload_seq: AtomicU64::new(0),
        cleanup_ops: AtomicU64::new(0),
        address: PieceTextAddress {
            table: TABLE.to_string(),
            row_id: fixture.row_id,
            column: COL.to_string(),
        },
    });

    let text = "a🌍b😀𐐷";
    area.append_string(text).await?;
    log_new_accept(&shared, AcceptedKind::Insert, vec![text.to_string()]).await?;

    let accepted = {
        let log = shared.log.lock().await;
        log.records.clone()
    };
    let offline = replay_with_actual_planner(&accepted)?;
    assert_eq!(area.snapshot().await?, text);
    assert_eq!(offline.snapshot, text);
    Ok(())
}

async fn driver_loop(
    client_name: &'static str,
    area: PieceTextArea,
    shared: Arc<SharedStress>,
    seed: u64,
    iters: usize,
) -> Result<()> {
    let mut rng = SmallRng::seed_from_u64(seed);

    for _ in 0..iters {
        let delay_ms = rng.random_range(0..=5);
        let op_roll = rng.random_range(0..100);
        // Cleanup is infrequent so tombstones accumulate into larger,
        // multi-run chunks between passes (closer to the production threshold).
        let do_cleanup = rng.random_bool(0.05);

        {
            let _serial_submit = shared.submit_gate.lock().await;
            area.sync().await?;
            let snapshot = area.snapshot().await?;
            let doc_len = snapshot.chars().count();
            let protected = shared
                .protected_chars
                .load(Ordering::SeqCst)
                .min(doc_len as u64) as usize;

            if op_roll < 30 {
                // Same-coordinate insert at the head: builds the LIFO-protected
                // prefix that `assert_lifo_protected_prefix` checks.
                let payload = next_payload(client_name, &shared, &mut rng, "H");
                area.insert_at_coord(BufferCoord::DOCUMENT_START, &payload)
                    .await?;
                log_new_accept(
                    &shared,
                    AcceptedKind::SameCoordInsert,
                    vec![payload.clone()],
                )
                .await?;
                shared
                    .protected_chars
                    .fetch_add(payload.chars().count() as u64, Ordering::SeqCst);
            } else if op_roll < 75 {
                let payload = next_payload(client_name, &shared, &mut rng, "I");
                let pos = rng.random_range(protected..=doc_len);
                area.insert_string(pos, &payload).await?;
                log_new_accept(&shared, AcceptedKind::Insert, vec![payload]).await?;
            } else {
                let delete_span = (doc_len - protected).min(10);
                if delete_span > 0 {
                    let start = rng.random_range(protected..doc_len);
                    let max_len = (doc_len - start).min(delete_span);
                    let len = rng.random_range(1..=max_len);
                    area.delete_range(start, start + len).await?;
                    log_new_accept(&shared, AcceptedKind::Delete, Vec::new()).await?;
                }
            }

            // Occasionally interleave a forced server cleanup pass (a system op),
            // asserting the `_piecetext_pieces`/`_piecetext_buffers` structure stays well-formed
            // across it. The submit gate already serializes it with the edits.
            if do_cleanup {
                let mut state = shared.transport.state_for_tests().await;
                if let Err(e) = state.assert_piece_text_invariants(&shared.address) {
                    panic!("{client_name}: invariants violated before cleanup (seed {seed}): {e}");
                }
                let committed = state
                    .force_piece_text_cleanup_for_tests(&shared.address, LIST_NUMBER)
                    .await
                    .unwrap_or_else(|e| panic!("{client_name}: cleanup failed (seed {seed}): {e}"));
                if let Err(e) = state.assert_piece_text_invariants(&shared.address) {
                    panic!("{client_name}: invariants violated after cleanup (seed {seed}): {e}");
                }
                shared
                    .cleanup_ops
                    .fetch_add(committed as u64, Ordering::SeqCst);
            }
        }

        sleep(Duration::from_millis(delay_ms)).await;
    }

    Ok(())
}

fn next_payload(
    client_name: &str,
    shared: &SharedStress,
    rng: &mut SmallRng,
    prefix: &str,
) -> String {
    let seq = shared.payload_seq.fetch_add(1, Ordering::SeqCst);
    let target_len = rng.random_range(1..=50);
    let mut payload = format!("{prefix}{client_name}{seq:04}|");
    while payload.chars().count() < target_len {
        let c = if rng.random_bool(0.1) {
            ['🌍', '😀', '𐐷'][rng.random_range(0..3)]
        } else {
            (b'a' + rng.random_range(0..26)) as char
        };
        payload.push(c);
    }
    payload = payload.chars().take(target_len).collect();
    payload
}

async fn log_new_accept(
    shared: &SharedStress,
    kind: AcceptedKind,
    inserted_texts: Vec<String>,
) -> Result<()> {
    let mut log = shared.log.lock().await;
    let envelopes = drain_accepted_envelopes(&shared.transport, &mut log.next_change_index).await?;
    assert_eq!(
        envelopes.len(),
        1,
        "each successful public PieceTextArea operation in this stress harness must commit exactly one accepted edit",
    );
    let envelope = envelopes.into_iter().next().unwrap();
    let canonical_bytes = envelope
        .canonical_bytes()
        .map_err(|e| SdkError::SerializationError(e.to_string()))?;
    assert!(!canonical_bytes.is_empty());
    log.records.push(AcceptedEdit {
        envelope,
        canonical_bytes,
        inserted_texts,
        kind,
    });
    Ok(())
}

async fn accepted_envelopes_since(
    transport: &LocalTransport,
    start: usize,
) -> Result<Vec<PieceTextEditEnvelopeV1>> {
    let state = transport.state_for_tests().await;
    state.changelog.changes[start..]
        .iter()
        .filter_map(|change| PieceTextEditEnvelopeV1::decode_from_entry(change).ok())
        .map(Ok)
        .collect()
}

async fn drain_accepted_envelopes(
    transport: &LocalTransport,
    next_change_index: &mut usize,
) -> Result<Vec<PieceTextEditEnvelopeV1>> {
    let state = transport.state_for_tests().await;
    let mut out = Vec::new();
    while *next_change_index < state.changelog.changes.len() {
        let change = &state.changelog.changes[*next_change_index];
        if let Ok(envelope) = PieceTextEditEnvelopeV1::decode_from_entry(change) {
            out.push(envelope);
        }
        *next_change_index += 1;
    }
    Ok(out)
}

struct OfflineFold {
    snapshot: String,
    op_ids: HashSet<[u8; 16]>,
}

/// Re-fold the accepted edit log offline through the in-memory model planner
/// (`plan_edit`) and return the rendered snapshot for cross-checking against the
/// live SDK state. `plan_edit` is the pure test/model planner, not the
/// production verifier — production runs the indexed overlay planner inside
/// `PieceTextEditOp` — but it shares the same coordinate-resolution and splice
/// algorithm, so it serves as an independent oracle for these stress runs.
fn replay_with_actual_planner(records: &[AcceptedEdit]) -> Result<OfflineFold> {
    let mut pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 0,
        tail_id: 0,
        pieces: Vec::new(),
        pre_piece_next_id: 1,
    };
    let mut buffers = BufferSnapshot {
        buffers: Vec::new(),
        pre_buffers_next_id: 1,
    };
    let mut buffer_contents: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut op_ids = HashSet::new();

    for record in records {
        if !op_ids.insert(record.envelope.op_id) {
            return Err(SdkError::ValidationError(
                "duplicate accepted op_id in fold log".to_string(),
            ));
        }

        let output = plan_edit(PlannerInput {
            envelope: &record.envelope,
            pieces: pieces.clone(),
            buffers: buffers.clone(),
            author_id: 1,
        })
        .map_err(|e| {
            SdkError::ValidationError(format!("offline piece-text planner failed: {e}"))
        })?;

        let expected_insert_count = record
            .envelope
            .edit
            .ops
            .iter()
            .filter(|op| matches!(op, PieceTextEditItemManifest::Insert { .. }))
            .count();
        assert_eq!(expected_insert_count, record.inserted_texts.len());
        assert_eq!(output.buffer_inserts.len(), record.inserted_texts.len());

        for (buffer, contents) in output
            .buffer_inserts
            .iter()
            .zip(record.inserted_texts.iter())
        {
            buffer_contents.insert(buffer.new_id, encode_utf32le(contents));
        }

        apply_planner_output(&mut pieces, &mut buffers, output)?;
    }

    let snapshot = render_snapshot(&pieces, &buffer_contents)?;
    Ok(OfflineFold { snapshot, op_ids })
}

fn apply_planner_output(
    pieces: &mut PieceSnapshot,
    buffers: &mut BufferSnapshot,
    output: encrypted_spaces_changelog_core::piece_text_planner::PlannerOutput,
) -> Result<()> {
    for update in output.piece_updates {
        let row = pieces
            .pieces
            .iter_mut()
            .find(|row| row.id == update.id)
            .ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "planner updated missing piece row {}",
                    update.id
                ))
            })?;
        if let Some(prev_id) = update.prev_id {
            row.prev_id = prev_id;
        }
        if let Some(next_id) = update.next_id {
            row.next_id = next_id;
        }
        if let Some(coord) = update.coord {
            row.coord = coord;
        }
    }

    for insert in output.piece_inserts {
        pieces.pieces.push(PieceRow {
            id: insert.new_id,
            list_number: insert.list_number,
            prev_id: insert.prev_id,
            next_id: insert.next_id,
            coord: insert.coord,
        });
    }
    pieces.pieces.sort_by_key(|row| row.id);

    if let Some(head_id) = output.head_update {
        pieces.head_id = head_id;
    }
    if let Some(tail_id) = output.tail_update {
        pieces.tail_id = tail_id;
    }
    if let Some(next_id) = output.piece_next_id_post {
        pieces.pre_piece_next_id = next_id;
    }

    for insert in output.buffer_inserts {
        buffers.buffers.push(BufferMeta {
            id: insert.new_id,
            owner_table: insert.owner_table,
            owner_row_id: insert.owner_row_id,
            owner_column: insert.owner_column,
            author_id: insert.author_id,
            len_bytes: insert.len_bytes,
        });
    }
    buffers.buffers.sort_by_key(|buffer| buffer.id);
    if let Some(next_id) = output.buffers_next_id_post {
        buffers.pre_buffers_next_id = next_id;
    }

    Ok(())
}

fn render_snapshot(
    pieces: &PieceSnapshot,
    buffer_contents: &HashMap<i64, Vec<u8>>,
) -> Result<String> {
    let by_id: HashMap<i64, &PieceRow> = pieces.pieces.iter().map(|row| (row.id, row)).collect();
    let mut out = String::new();
    let mut current = pieces.head_id;
    let mut seen = HashSet::new();

    while current != 0 {
        if !seen.insert(current) {
            return Err(SdkError::ValidationError(
                "offline fold detected a piece chain cycle".to_string(),
            ));
        }
        let piece = by_id.get(&current).ok_or_else(|| {
            SdkError::ValidationError(format!("offline fold missing piece row {current}"))
        })?;
        if !piece.coord.tombstone {
            let contents = buffer_contents.get(&piece.coord.buffer_id).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "offline fold missing buffer {}",
                    piece.coord.buffer_id
                ))
            })?;
            let start = piece.coord.start_byte as usize;
            let end = start
                .checked_add(piece.coord.len_bytes as usize)
                .ok_or_else(|| {
                    SdkError::ValidationError(format!(
                        "offline fold piece {} byte range overflow",
                        piece.id
                    ))
                })?;
            if !start.is_multiple_of(4) || !end.is_multiple_of(4) {
                return Err(SdkError::ValidationError(format!(
                    "offline fold piece {} has non-UTF-32-aligned range [{start}, {end})",
                    piece.id
                )));
            }
            let slice = contents.get(start..end).ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "offline fold piece {} range [{start}, {end}) exceeds buffer {} bytes",
                    piece.id,
                    contents.len()
                ))
            })?;
            out.push_str(&decode_utf32le_lossy(slice));
        }
        current = piece.next_id;
    }

    Ok(out)
}

fn encode_utf32le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.chars().count() * 4);
    for ch in text.chars() {
        out.extend_from_slice(&(ch as u32).to_le_bytes());
    }
    out
}

fn decode_utf32le_lossy(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut chunks = bytes.chunks_exact(4);
    for chunk in &mut chunks {
        let unit = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        out.push(char::from_u32(unit).unwrap_or('\u{FFFD}'));
    }
    if !chunks.remainder().is_empty() {
        out.push('\u{FFFD}');
    }
    out
}

async fn sync_until_quiescent(
    alice: &PieceTextArea,
    bob: &PieceTextArea,
) -> Result<(String, String)> {
    let mut previous: Option<(String, String)> = None;
    for _ in 0..10 {
        alice.sync().await?;
        bob.sync().await?;
        let current = (alice.snapshot().await?, bob.snapshot().await?);
        if previous.as_ref() == Some(&current) {
            return Ok(current);
        }
        previous = Some(current);
    }
    previous.ok_or_else(|| {
        SdkError::ValidationError("quiescence loop never produced a snapshot".to_string())
    })
}

fn assert_lifo_protected_prefix(records: &[AcceptedEdit], final_snapshot: &str) {
    let protected: Vec<&str> = records
        .iter()
        .filter(|record| matches!(record.kind, AcceptedKind::SameCoordInsert))
        .flat_map(|record| record.inserted_texts.iter().map(String::as_str))
        .collect();
    assert!(
        protected.len() >= 2,
        "stress run must accept at least two same-coordinate inserts",
    );
    let expected_prefix: String = protected.iter().rev().copied().collect();
    assert!(
        final_snapshot.starts_with(&expected_prefix),
        "same-coordinate inserts must render newest-first in the final document",
    );
}

fn stress_seed() -> u64 {
    if let Some(seed) = std::env::var("FUZZ_SEED").ok().and_then(|v| v.parse().ok()) {
        return seed;
    }
    rand::rngs::OsRng.try_next_u64().expect("OS RNG failed")
}
