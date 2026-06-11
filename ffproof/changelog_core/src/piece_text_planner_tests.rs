//! Model tests for the pure piece-table edit planner.
//!
//! All tests construct an in-memory [`PieceSnapshot`]/[`BufferSnapshot`],
//! build an envelope manifest, run [`plan_edit`], and assert the planner's
//! `PlannerOutput` (write batch + trace) matches the coordinate-resolution
//! and splice algorithms.

use super::*;
use crate::piece_text::{
    BufferCoord, InsertedBufferManifest, PieceCoord, PieceTextAddress, PieceTextEditEnvelopeV1,
    PieceTextEditItemManifest, PieceTextEditManifest, PIECE_TEXT_ENVELOPE_VERSION_V1,
};

const TABLE: &str = "channels";
const COLUMN: &str = "notes_pieces";
const PARENT_ROW: i64 = 7;
const LIST_NUMBER: i64 = 1;
const AUTHOR: i64 = 100;

fn address() -> PieceTextAddress {
    PieceTextAddress {
        table: TABLE.to_string(),
        row_id: PARENT_ROW,
        column: COLUMN.to_string(),
    }
}

fn envelope(ops: Vec<PieceTextEditItemManifest>) -> PieceTextEditEnvelopeV1 {
    PieceTextEditEnvelopeV1 {
        version: PIECE_TEXT_ENVELOPE_VERSION_V1,
        op_id: [1u8; 16],
        address: address(),
        edit: PieceTextEditManifest { ops },
    }
}

fn buffer_meta(id: i64, len_bytes: u32) -> BufferMeta {
    BufferMeta {
        id,
        owner_table: TABLE.to_string(),
        owner_row_id: PARENT_ROW,
        owner_column: COLUMN.to_string(),
        author_id: AUTHOR,
        len_bytes,
    }
}

fn manifest(len_bytes: u32, byte_marker: u8) -> InsertedBufferManifest {
    InsertedBufferManifest {
        len_bytes,
        ciphertext_len: len_bytes + 16,
        ciphertext_value_hash: [byte_marker; 32],
    }
}

fn run(
    pieces: PieceSnapshot,
    buffers: BufferSnapshot,
    env: &PieceTextEditEnvelopeV1,
) -> Result<PlannerOutput, PlannerError> {
    plan_edit(PlannerInput {
        envelope: env,
        pieces,
        buffers,
        author_id: AUTHOR,
    })
}

fn run_unwrap(
    pieces: PieceSnapshot,
    buffers: BufferSnapshot,
    env: &PieceTextEditEnvelopeV1,
) -> PlannerOutput {
    run(pieces, buffers, env).expect("planner should succeed")
}

fn empty_snapshot(pre_piece_next: i64) -> PieceSnapshot {
    PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 0,
        tail_id: 0,
        pieces: vec![],
        pre_piece_next_id: pre_piece_next,
    }
}

fn empty_buffers(pre_buffers_next: i64) -> BufferSnapshot {
    BufferSnapshot {
        buffers: vec![],
        pre_buffers_next_id: pre_buffers_next,
    }
}

// ---------- inserts ----------

#[test]
fn empty_insert_into_empty_document() {
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord::DOCUMENT_START,
        inserted: manifest(5, 0xAA),
    }]);
    let out = run_unwrap(empty_snapshot(1), empty_buffers(1), &env);

    assert_eq!(out.piece_inserts.len(), 1);
    assert_eq!(out.piece_inserts[0].new_id, 1);
    assert_eq!(out.piece_inserts[0].prev_id, 0);
    assert_eq!(out.piece_inserts[0].next_id, 0);
    assert_eq!(out.piece_inserts[0].coord.buffer_id, 1);
    assert_eq!(out.piece_inserts[0].coord.start_byte, 0);
    assert_eq!(out.piece_inserts[0].coord.len_bytes, 5);
    assert!(!out.piece_inserts[0].coord.tombstone);

    assert!(out.piece_updates.is_empty());

    assert_eq!(out.buffer_inserts.len(), 1);
    assert_eq!(out.buffer_inserts[0].new_id, 1);
    assert_eq!(out.buffer_inserts[0].len_bytes, 5);
    assert_eq!(out.buffer_inserts[0].author_id, AUTHOR);

    assert_eq!(out.head_update, Some(1));
    assert_eq!(out.tail_update, Some(1));
    assert_eq!(out.piece_next_id_post, Some(2));
    assert_eq!(out.buffers_next_id_post, Some(2));
}

fn one_piece_doc() -> (PieceSnapshot, BufferSnapshot) {
    // List has piece id=10 covering buffer 5 bytes [0..5).
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 10,
        tail_id: 10,
        pieces: vec![PieceRow {
            id: 10,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 5,
                start_byte: 0,
                len_bytes: 5,
                tombstone: false,
            },
        }],
        pre_piece_next_id: 11,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 5)],
        pre_buffers_next_id: 6,
    };
    (pieces, buffers)
}

#[test]
fn append_after_existing_piece() {
    let (pieces, buffers) = one_piece_doc();
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 5,
        },
        inserted: manifest(3, 0xBB),
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    assert_eq!(out.piece_inserts.len(), 1);
    let n = &out.piece_inserts[0];
    assert_eq!(n.new_id, 11);
    assert_eq!(n.prev_id, 10);
    assert_eq!(n.next_id, 0);
    assert_eq!(n.coord.buffer_id, 6);
    assert_eq!(n.coord.len_bytes, 3);

    // Existing row 10 only learned a new next_id; no coord change, no prev change.
    assert_eq!(out.piece_updates.len(), 1);
    assert_eq!(out.piece_updates[0].id, 10);
    assert_eq!(out.piece_updates[0].next_id, Some(11));
    assert!(out.piece_updates[0].prev_id.is_none());
    assert!(out.piece_updates[0].coord.is_none());

    // Tail moved from 10 to 11; head stayed at 10.
    assert_eq!(out.head_update, None);
    assert_eq!(out.tail_update, Some(11));
}

#[test]
fn split_insert_inside_a_piece() {
    let (pieces, buffers) = one_piece_doc();
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 2,
        },
        inserted: manifest(4, 0xCC),
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    // Two new piece rows: N (new text) then R (right half of the split).
    assert_eq!(out.piece_inserts.len(), 2);
    let n = &out.piece_inserts[0];
    let r = &out.piece_inserts[1];
    assert_eq!(n.new_id, 11);
    assert_eq!(r.new_id, 12);
    assert!(n.new_id < r.new_id);

    assert_eq!(n.prev_id, 10);
    assert_eq!(n.next_id, 12);
    assert_eq!(n.coord.buffer_id, 6);
    assert_eq!(n.coord.start_byte, 0);
    assert_eq!(n.coord.len_bytes, 4);

    assert_eq!(r.prev_id, 11);
    assert_eq!(r.next_id, 0);
    assert_eq!(r.coord.buffer_id, 5);
    assert_eq!(r.coord.start_byte, 2);
    assert_eq!(r.coord.len_bytes, 3);
    assert!(!r.coord.tombstone);

    // Existing row 10: len_bytes truncated to 2, next_id rewritten to 11.
    assert_eq!(out.piece_updates.len(), 1);
    let p_upd = &out.piece_updates[0];
    assert_eq!(p_upd.id, 10);
    assert_eq!(p_upd.next_id, Some(11));
    assert_eq!(
        p_upd.coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 0,
            len_bytes: 2,
            tombstone: false,
        })
    );
    assert!(p_upd.prev_id.is_none());

    assert_eq!(out.head_update, None); // 10 still head.
    assert_eq!(out.tail_update, Some(12)); // R is the new tail.
    assert_eq!(out.piece_next_id_post, Some(13));
}

#[test]
fn same_coordinate_inserts_render_newest_first() {
    // Empty document. Insert at DOCUMENT_START three times in one edit. The
    // chain should end up: T3 -> T2 -> T1 (newest first).
    let env = envelope(vec![
        PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: manifest(1, 0x01),
        },
        PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: manifest(1, 0x02),
        },
        PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: manifest(1, 0x03),
        },
    ]);
    let out = run_unwrap(empty_snapshot(1), empty_buffers(1), &env);

    assert_eq!(out.piece_inserts.len(), 3);
    let t1 = &out.piece_inserts[0];
    let t2 = &out.piece_inserts[1];
    let t3 = &out.piece_inserts[2];
    // Sequential id assignment.
    assert_eq!(t1.new_id, 1);
    assert_eq!(t2.new_id, 2);
    assert_eq!(t3.new_id, 3);
    // Chain: head -> t3 -> t2 -> t1 -> tail.
    assert_eq!(t3.prev_id, 0);
    assert_eq!(t3.next_id, 2);
    assert_eq!(t2.prev_id, 3);
    assert_eq!(t2.next_id, 1);
    assert_eq!(t1.prev_id, 2);
    assert_eq!(t1.next_id, 0);
    // Head ends up at t3 (newest); tail stays at t1 (oldest).
    assert_eq!(out.head_update, Some(3));
    assert_eq!(out.tail_update, Some(1));
}

#[test]
fn same_coordinate_after_existing_piece() {
    // Existing piece P (id=10, buffer 5, len 5). Insert at end of P twice; the
    // second insertion should land between P and the first inserted piece.
    let (pieces, buffers) = one_piece_doc();
    let env = envelope(vec![
        PieceTextEditItemManifest::Insert {
            at: BufferCoord {
                buffer_id: 5,
                byte_pos: 5,
            },
            inserted: manifest(2, 0xAA),
        },
        PieceTextEditItemManifest::Insert {
            at: BufferCoord {
                buffer_id: 5,
                byte_pos: 5,
            },
            inserted: manifest(3, 0xBB),
        },
    ]);
    let out = run_unwrap(pieces, buffers, &env);

    assert_eq!(out.piece_inserts.len(), 2);
    let n1 = &out.piece_inserts[0];
    let n2 = &out.piece_inserts[1];
    assert_eq!(n1.new_id, 11);
    assert_eq!(n2.new_id, 12);
    // Chain: 10 -> n2 -> n1 (newest first after P).
    assert_eq!(n2.prev_id, 10);
    assert_eq!(n2.next_id, 11);
    assert_eq!(n1.prev_id, 12);
    assert_eq!(n1.next_id, 0);
    // Tail moved from 10 to 11 (n1 is the new tail).
    assert_eq!(out.tail_update, Some(11));
    // Head unchanged.
    assert_eq!(out.head_update, None);

    // Existing row 10: only next_id changed.
    assert_eq!(out.piece_updates.len(), 1);
    assert_eq!(out.piece_updates[0].id, 10);
    assert_eq!(out.piece_updates[0].next_id, Some(12));
    assert!(out.piece_updates[0].prev_id.is_none());
    assert!(out.piece_updates[0].coord.is_none());
}

// ---------- tombstone clamp ----------

fn three_piece_doc_middle_tomb() -> (PieceSnapshot, BufferSnapshot) {
    // A(live, buffer=5, [0..2)) -> B(tomb, buffer=5, [2..3)) -> C(live, buffer=5, [3..5))
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 2,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 3,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 4,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 5)],
        pre_buffers_next_id: 6,
    };
    (pieces, buffers)
}

#[test]
fn insert_inside_tombstone_back_clamps_to_live_predecessor() {
    let (pieces, buffers) = three_piece_doc_middle_tomb();
    // byte_pos=2 lands at boundary where A ends and B starts. §4.1 boundary
    // tie-break: predecessor wins, matched=A. A is live, no clamp.
    let env_predecessor = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 2,
        },
        inserted: manifest(2, 0x11),
    }]);
    let out = run_unwrap(pieces.clone(), buffers.clone(), &env_predecessor);
    // No clamp walk recorded (matched live).
    assert!(out.trace.clamp_walks.is_empty());
    // Splice after A (id=1).
    assert_eq!(out.piece_inserts.len(), 1);
    let n = &out.piece_inserts[0];
    assert_eq!(n.prev_id, 1);
    assert_eq!(n.next_id, 2);

    // byte_pos in the interior of B (buffer offset 2..3). Tombstone clamp.
    let env_inside = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 2, // start of B; predecessor candidate would still win
        },
        inserted: manifest(1, 0x22),
    }]);
    // The above resolves the predecessor (A) just like the previous case.
    // Construct a tombstone-only middle by widening B so the boundary at 3
    // sits at the end of B (predecessor candidate = B). Here, swap to that
    // simpler shape.
    let _ = env_inside;
    drop(out);

    // Simpler tombstone-clamp scenario: byte_pos at end of B (=3). With both
    // B and C as candidates: predecessor=B (tomb), successor=C (live).
    // §4.1 picks predecessor=B; clamp backward through B to find live
    // predecessor A.
    let env_clamp = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 3,
        },
        inserted: manifest(2, 0x33),
    }]);
    let out = run_unwrap(pieces, buffers, &env_clamp);
    assert_eq!(out.trace.clamp_walks.len(), 1);
    let walk = &out.trace.clamp_walks[0];
    assert_eq!(walk.start_row_id, 2);
    assert_eq!(walk.direction, ClampDirection::Backward);
    assert_eq!(walk.purpose, ResolvePurpose::InsertAnchor);
    assert_eq!(walk.hops, 1);
    assert_eq!(walk.end_row_id, Some(1));

    // New piece spliced after live A (id=1), before B (current next of A).
    let n = &out.piece_inserts[0];
    assert_eq!(n.prev_id, 1);
    assert_eq!(n.next_id, 2);
}

#[test]
fn tombstone_clamp_walks_full_run_backward_for_insert_anchor() {
    // A(live) -> B(tomb) -> C(tomb) -> D(tomb) -> E(live), all sharing
    // buffer 5 with adjacent ranges. Insert at byte_pos at the boundary
    // C->D (predecessor=C tomb) must back-clamp through C and B to A.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 5,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 0,
                    len_bytes: 1,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 1,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 4,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 2,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 4,
                list_number: LIST_NUMBER,
                prev_id: 3,
                next_id: 5,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 3,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 5,
                list_number: LIST_NUMBER,
                prev_id: 4,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 4,
                    len_bytes: 1,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 6,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 5)],
        pre_buffers_next_id: 6,
    };

    // byte_pos=3 = boundary between C ([2,3)) and D ([3,4)): predecessor=C
    // (tomb), successor=D (tomb). Predecessor wins; back-clamp from C
    // through B to A. That is two hops (C, B), landing on A.
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 3,
        },
        inserted: manifest(2, 0x44),
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    let backward_walks: Vec<&ClampWalk> = out
        .trace
        .clamp_walks
        .iter()
        .filter(|w| w.direction == ClampDirection::Backward)
        .collect();
    assert_eq!(backward_walks.len(), 1);
    let bw = backward_walks[0];
    assert_eq!(bw.purpose, ResolvePurpose::InsertAnchor);
    assert_eq!(bw.start_row_id, 3);
    // hops counts the tombstones C, B before landing on A.
    assert_eq!(bw.hops, 2);
    assert_eq!(bw.end_row_id, Some(1));

    // The new piece splices after live A (id=1), before B (current next of A).
    let n = &out.piece_inserts[0];
    assert_eq!(n.prev_id, 1);
    assert_eq!(n.next_id, 2);
}

#[test]
fn tombstone_clamp_walks_full_run_forward_for_delete_start() {
    // Build chain: A(live) -> B(tomb) -> C(tomb) -> D(tomb) -> E(live), all
    // sharing buffer 5 with adjacent ranges. DeleteStart at byte_pos in B's
    // range should forward-clamp through all three tombstones to E.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 5,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 0,
                    len_bytes: 1,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 1,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 4,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 2,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 4,
                list_number: LIST_NUMBER,
                prev_id: 3,
                next_id: 5,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 3,
                    len_bytes: 1,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 5,
                list_number: LIST_NUMBER,
                prev_id: 4,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 4,
                    len_bytes: 1,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 6,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 5)],
        pre_buffers_next_id: 6,
    };

    // Delete from byte_pos=2 (boundary B->C, predecessor=B (tomb)) to end of E.
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 5,
            byte_pos: 2,
        },
        end: BufferCoord {
            buffer_id: 5,
            byte_pos: 5,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    // We should see two clamp walks: one for DeleteStart (forward from B),
    // one for DeleteEnd (which lands on live E with no clamp).
    let forward_walks: Vec<&ClampWalk> = out
        .trace
        .clamp_walks
        .iter()
        .filter(|w| w.direction == ClampDirection::Forward)
        .collect();
    assert_eq!(forward_walks.len(), 1);
    let fw = forward_walks[0];
    assert_eq!(fw.purpose, ResolvePurpose::DeleteStart);
    assert_eq!(fw.start_row_id, 2);
    // Walks B -> C -> D, then lands on E. hops counts the tombstones
    // skipped (3): B, C, D.
    assert_eq!(fw.hops, 3);
    assert_eq!(fw.end_row_id, Some(5));

    // The delete tombstones E (the only live row in the range past A).
    let updates_for_e: Vec<&PieceRowUpdate> =
        out.piece_updates.iter().filter(|u| u.id == 5).collect();
    assert_eq!(updates_for_e.len(), 1);
    assert_eq!(
        updates_for_e[0].coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 4,
            len_bytes: 1,
            tombstone: true,
        })
    );
}

// ---------- deletes ----------

fn three_piece_doc_live() -> (PieceSnapshot, BufferSnapshot) {
    // A(live, buf 1, [0..3)), B(live, buf 2, [0..4)), C(live, buf 3, [0..2))
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: 0,
                    len_bytes: 3,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 2,
                    start_byte: 0,
                    len_bytes: 4,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 3,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 4,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(1, 3), buffer_meta(2, 4), buffer_meta(3, 2)],
        pre_buffers_next_id: 4,
    };
    (pieces, buffers)
}

#[test]
fn whole_piece_delete_only_flips_tombstone() {
    let (pieces, buffers) = three_piece_doc_live();
    // Delete exactly B's range.
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 2,
            byte_pos: 0,
        },
        end: BufferCoord {
            buffer_id: 2,
            byte_pos: 4,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    assert!(out.piece_inserts.is_empty());
    assert!(out.buffer_inserts.is_empty());
    assert_eq!(out.piece_updates.len(), 1);
    let upd = &out.piece_updates[0];
    assert_eq!(upd.id, 2);
    assert!(upd.prev_id.is_none());
    assert!(upd.next_id.is_none());
    assert_eq!(
        upd.coord,
        Some(PieceCoord {
            buffer_id: 2,
            start_byte: 0,
            len_bytes: 4,
            tombstone: true,
        })
    );
    // No counter bumps (no new piece rows or buffer rows).
    assert_eq!(out.piece_next_id_post, None);
    assert_eq!(out.buffers_next_id_post, None);
    // Adjacency unchanged: head=1, tail=3.
    assert_eq!(out.head_update, None);
    assert_eq!(out.tail_update, None);
}

#[test]
fn ragged_center_delete_within_one_piece() {
    // Single-piece doc, buffer 5 [0..10). Delete [3, 7). Expect M_deleted then
    // R_right (sequential ids), and P shrinks to len_bytes 3.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 10,
        tail_id: 10,
        pieces: vec![PieceRow {
            id: 10,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 5,
                start_byte: 0,
                len_bytes: 10,
                tombstone: false,
            },
        }],
        pre_piece_next_id: 11,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 10)],
        pre_buffers_next_id: 6,
    };
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 5,
            byte_pos: 3,
        },
        end: BufferCoord {
            buffer_id: 5,
            byte_pos: 7,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    assert_eq!(out.piece_inserts.len(), 2);
    let m = &out.piece_inserts[0];
    let r = &out.piece_inserts[1];
    assert_eq!(m.new_id, 11);
    assert_eq!(r.new_id, 12);
    assert!(m.coord.tombstone);
    assert_eq!(m.coord.start_byte, 3);
    assert_eq!(m.coord.len_bytes, 4);
    assert!(!r.coord.tombstone);
    assert_eq!(r.coord.start_byte, 7);
    assert_eq!(r.coord.len_bytes, 3);

    assert_eq!(m.prev_id, 10);
    assert_eq!(m.next_id, 12);
    assert_eq!(r.prev_id, 11);
    assert_eq!(r.next_id, 0);

    assert_eq!(out.piece_updates.len(), 1);
    let p_upd = &out.piece_updates[0];
    assert_eq!(p_upd.id, 10);
    assert_eq!(p_upd.next_id, Some(11));
    assert_eq!(
        p_upd.coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 0,
            len_bytes: 3,
            tombstone: false,
        })
    );

    // P was tail; R becomes new tail.
    assert_eq!(out.tail_update, Some(12));
    assert_eq!(out.head_update, None);
    assert_eq!(out.piece_next_id_post, Some(13));
}

#[test]
fn ragged_left_delete_within_one_piece() {
    // Buffer 5 [0..10). Delete [3, 10).
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 10,
        tail_id: 10,
        pieces: vec![PieceRow {
            id: 10,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 5,
                start_byte: 0,
                len_bytes: 10,
                tombstone: false,
            },
        }],
        pre_piece_next_id: 11,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 10)],
        pre_buffers_next_id: 6,
    };
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 5,
            byte_pos: 3,
        },
        end: BufferCoord {
            buffer_id: 5,
            byte_pos: 10,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    // One new tombstone piece (right suffix of original P).
    assert_eq!(out.piece_inserts.len(), 1);
    let m = &out.piece_inserts[0];
    assert_eq!(m.new_id, 11);
    assert!(m.coord.tombstone);
    assert_eq!(m.coord.start_byte, 3);
    assert_eq!(m.coord.len_bytes, 7);
    assert_eq!(m.prev_id, 10);
    assert_eq!(m.next_id, 0);

    // P shrinks to len 3.
    assert_eq!(out.piece_updates.len(), 1);
    let p_upd = &out.piece_updates[0];
    assert_eq!(p_upd.id, 10);
    assert_eq!(p_upd.next_id, Some(11));
    assert_eq!(
        p_upd.coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 0,
            len_bytes: 3,
            tombstone: false,
        })
    );

    assert_eq!(out.tail_update, Some(11));
    assert_eq!(out.head_update, None);
}

#[test]
fn ragged_right_delete_within_one_piece() {
    // Buffer 5 [0..10). Delete [0, 7).
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 10,
        tail_id: 10,
        pieces: vec![PieceRow {
            id: 10,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 5,
                start_byte: 0,
                len_bytes: 10,
                tombstone: false,
            },
        }],
        pre_piece_next_id: 11,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 10)],
        pre_buffers_next_id: 6,
    };
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 5,
            byte_pos: 0,
        },
        end: BufferCoord {
            buffer_id: 5,
            byte_pos: 7,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    // One new live piece (right suffix); original P shrinks to the deleted
    // left prefix and is tombstoned.
    assert_eq!(out.piece_inserts.len(), 1);
    let m = &out.piece_inserts[0];
    assert!(!m.coord.tombstone);
    assert_eq!(m.coord.start_byte, 7);
    assert_eq!(m.coord.len_bytes, 3);
    assert_eq!(m.prev_id, 10);
    assert_eq!(m.next_id, 0);

    assert_eq!(out.piece_updates.len(), 1);
    let p_upd = &out.piece_updates[0];
    assert_eq!(p_upd.id, 10);
    assert_eq!(p_upd.next_id, Some(11));
    assert_eq!(
        p_upd.coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 0,
            len_bytes: 7,
            tombstone: true,
        })
    );

    assert_eq!(out.tail_update, Some(11));
    assert_eq!(out.head_update, None);
}

#[test]
fn both_ragged_delete_left_then_right_ordering() {
    // A(live, buf 1, [0..4)), B(live, buf 2, [0..3)), C(live, buf 3, [0..5))
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: 0,
                    len_bytes: 4,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 2,
                    start_byte: 0,
                    len_bytes: 3,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 3,
                    start_byte: 0,
                    len_bytes: 5,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 4,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(1, 4), buffer_meta(2, 3), buffer_meta(3, 5)],
        pre_buffers_next_id: 4,
    };
    // Delete from middle of A (byte 2 of buffer 1) to middle of C (byte 3 of
    // buffer 3). Expect ML_deleted (lower id) before MR_right (higher id),
    // plus B tombstoned in place.
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 1,
            byte_pos: 2,
        },
        end: BufferCoord {
            buffer_id: 3,
            byte_pos: 3,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);

    assert_eq!(out.piece_inserts.len(), 2);
    let ml = &out.piece_inserts[0];
    let mr = &out.piece_inserts[1];
    assert_eq!(ml.new_id, 4);
    assert_eq!(mr.new_id, 5);
    assert!(ml.new_id < mr.new_id);

    // ML_deleted: right suffix of A, tombstoned.
    assert!(ml.coord.tombstone);
    assert_eq!(ml.coord.buffer_id, 1);
    assert_eq!(ml.coord.start_byte, 2);
    assert_eq!(ml.coord.len_bytes, 2);
    assert_eq!(ml.prev_id, 1);
    assert_eq!(ml.next_id, 2);

    // MR_right: right suffix of C, live.
    assert!(!mr.coord.tombstone);
    assert_eq!(mr.coord.buffer_id, 3);
    assert_eq!(mr.coord.start_byte, 3);
    assert_eq!(mr.coord.len_bytes, 2);
    assert_eq!(mr.prev_id, 3);
    assert_eq!(mr.next_id, 0);

    // Existing rows updates:
    // - A (1): coord -> len 2, next_id -> ML's id (4).
    // - B (2): tombstone flip; prev_id -> ML's id (4).
    // - C (3): coord -> len 3 + tombstone, next_id -> MR's id (5).
    let updates: std::collections::HashMap<i64, &PieceRowUpdate> =
        out.piece_updates.iter().map(|u| (u.id, u)).collect();
    assert_eq!(updates.len(), 3);

    let a_upd = updates[&1];
    assert_eq!(a_upd.next_id, Some(4));
    assert_eq!(
        a_upd.coord,
        Some(PieceCoord {
            buffer_id: 1,
            start_byte: 0,
            len_bytes: 2,
            tombstone: false,
        })
    );
    assert!(a_upd.prev_id.is_none());

    let b_upd = updates[&2];
    assert_eq!(b_upd.prev_id, Some(4));
    assert_eq!(
        b_upd.coord,
        Some(PieceCoord {
            buffer_id: 2,
            start_byte: 0,
            len_bytes: 3,
            tombstone: true,
        })
    );
    assert!(b_upd.next_id.is_none());

    let c_upd = updates[&3];
    assert_eq!(c_upd.next_id, Some(5));
    assert_eq!(
        c_upd.coord,
        Some(PieceCoord {
            buffer_id: 3,
            start_byte: 0,
            len_bytes: 3,
            tombstone: true,
        })
    );
    assert!(c_upd.prev_id.is_none());

    // C was tail; MR_right is the new tail.
    assert_eq!(out.tail_update, Some(5));
    assert_eq!(out.head_update, None);
    assert_eq!(out.piece_next_id_post, Some(6));
}

// ---------- multi-op transactions ----------

#[test]
fn delete_then_insert_at_deleted_boundary() {
    // Buffer 5 [0..10). Delete [3, 7), then insert at byte_pos=3. After the
    // delete, P is len 3 (pre-existing, id=10) with M_deleted (new id 11) and
    // R_right (new id 12). The boundary at byte_pos=3 of buffer 5 sits at end
    // of P (predecessor) and start of M_deleted (tombstone successor); §4.1
    // picks predecessor=P. P is live, no clamp. New piece spliced after P,
    // before M_deleted.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 10,
        tail_id: 10,
        pieces: vec![PieceRow {
            id: 10,
            list_number: LIST_NUMBER,
            prev_id: 0,
            next_id: 0,
            coord: PieceCoord {
                buffer_id: 5,
                start_byte: 0,
                len_bytes: 10,
                tombstone: false,
            },
        }],
        pre_piece_next_id: 11,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 10)],
        pre_buffers_next_id: 6,
    };
    let env = envelope(vec![
        PieceTextEditItemManifest::Delete {
            start: BufferCoord {
                buffer_id: 5,
                byte_pos: 3,
            },
            end: BufferCoord {
                buffer_id: 5,
                byte_pos: 7,
            },
        },
        PieceTextEditItemManifest::Insert {
            at: BufferCoord {
                buffer_id: 5,
                byte_pos: 3,
            },
            inserted: manifest(2, 0xFE),
        },
    ]);
    let out = run_unwrap(pieces, buffers, &env);

    // Expect three new piece rows: M_deleted (11), R_right (12), then N (13).
    assert_eq!(out.piece_inserts.len(), 3);
    assert_eq!(out.piece_inserts[0].new_id, 11);
    assert_eq!(out.piece_inserts[1].new_id, 12);
    assert_eq!(out.piece_inserts[2].new_id, 13);

    // The third insert (N) is spliced after P (id=10), before M_deleted.
    let n = &out.piece_inserts[2];
    assert_eq!(n.prev_id, 10);
    assert_eq!(n.next_id, 11);

    // N should have buffer_id from the new buffer (id 6).
    assert_eq!(n.coord.buffer_id, 6);
    assert_eq!(n.coord.len_bytes, 2);

    // M_deleted's prev_id was originally P's id (10). After the second op,
    // the chain is P -> N -> M_deleted -> R_right. So M_deleted's final
    // prev_id is N's id (13). Since M_deleted is a *new* row, the planner
    // should reflect this via its insert payload (not as an update).
    assert_eq!(out.piece_inserts[0].prev_id, 13);
    assert_eq!(out.piece_inserts[0].next_id, 12);
    assert_eq!(out.piece_inserts[1].prev_id, 11);
    assert_eq!(out.piece_inserts[1].next_id, 0);

    // P (id=10) has its next_id rewritten to N (13) by the second op (it was
    // 11 after the delete). Coord shows the post-delete len=3.
    let p_upd = out
        .piece_updates
        .iter()
        .find(|u| u.id == 10)
        .expect("update for P");
    assert_eq!(p_upd.next_id, Some(13));
    assert_eq!(
        p_upd.coord,
        Some(PieceCoord {
            buffer_id: 5,
            start_byte: 0,
            len_bytes: 3,
            tombstone: false,
        })
    );

    assert_eq!(out.tail_update, Some(12));
    assert_eq!(out.head_update, None);
}

#[test]
fn overlapping_sequential_deletes_are_idempotent_in_overlap() {
    let (pieces, buffers) = three_piece_doc_live();
    // First delete A entirely. Second delete extends from middle of A to
    // middle of C, but A is already tombstoned, B is live, C will be ragged.
    let env = envelope(vec![
        PieceTextEditItemManifest::Delete {
            start: BufferCoord {
                buffer_id: 1,
                byte_pos: 0,
            },
            end: BufferCoord {
                buffer_id: 1,
                byte_pos: 3,
            },
        },
        PieceTextEditItemManifest::Delete {
            start: BufferCoord {
                buffer_id: 1,
                byte_pos: 2, // inside tombstoned A
            },
            end: BufferCoord {
                buffer_id: 3,
                byte_pos: 1,
            },
        },
    ]);
    let out = run_unwrap(pieces, buffers, &env);

    // Trace must show DeleteStart forward-clamping past tombstoned A.
    let forward_clamp_walks: Vec<&ClampWalk> = out
        .trace
        .clamp_walks
        .iter()
        .filter(|w| w.direction == ClampDirection::Forward)
        .collect();
    assert!(!forward_clamp_walks.is_empty());
    let fw = forward_clamp_walks[0];
    assert_eq!(fw.purpose, ResolvePurpose::DeleteStart);
    assert_eq!(fw.hops, 1);
    assert_eq!(fw.end_row_id, Some(2));

    // A is tombstoned exactly once (no double flip).
    let a_upd = out
        .piece_updates
        .iter()
        .find(|u| u.id == 1)
        .expect("update for A");
    assert_eq!(
        a_upd.coord.unwrap(),
        PieceCoord {
            buffer_id: 1,
            start_byte: 0,
            len_bytes: 3,
            tombstone: true,
        }
    );

    // B is wholly tombstoned.
    let b_upd = out
        .piece_updates
        .iter()
        .find(|u| u.id == 2)
        .expect("update for B");
    assert!(b_upd.coord.unwrap().tombstone);

    // C is ragged-right (left prefix tombstoned, right kept).
    assert_eq!(out.piece_inserts.len(), 1);
    let mr = &out.piece_inserts[0];
    assert!(!mr.coord.tombstone);
    assert_eq!(mr.coord.buffer_id, 3);
    assert_eq!(mr.coord.start_byte, 1);
    assert_eq!(mr.coord.len_bytes, 1);
}

#[test]
fn rejects_coord_targeting_buffer_allocated_in_same_edit() {
    // Insert allocates buffer id 1 (since pre_buffers_next_id = 1). Then a
    // second op references buffer_id = 1 — that must be rejected.
    let env = envelope(vec![
        PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: manifest(4, 0xAA),
        },
        PieceTextEditItemManifest::Insert {
            at: BufferCoord {
                buffer_id: 1,
                byte_pos: 2,
            },
            inserted: manifest(2, 0xBB),
        },
    ]);
    let err = run(empty_snapshot(1), empty_buffers(1), &env).expect_err("must reject");
    match err {
        PlannerError::InvalidCoordinate(msg) => {
            assert!(
                msg.contains("allocated by an earlier Insert"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidCoordinate, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_buffer_id() {
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 99,
            byte_pos: 0,
        },
        inserted: manifest(2, 0xCD),
    }]);
    let err = run(empty_snapshot(1), empty_buffers(1), &env).expect_err("must reject");
    match err {
        PlannerError::BufferNotFound { buffer_id } => assert_eq!(buffer_id, 99),
        other => panic!("expected BufferNotFound, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_byte_coordinate() {
    let (pieces, buffers) = one_piece_doc();
    // Buffer 5 has length 5; byte_pos 99 is past the end.
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 99,
        },
        inserted: manifest(1, 0xEE),
    }]);
    let err = run(pieces, buffers, &env).expect_err("must reject");
    match err {
        PlannerError::UnknownCoordinate { .. } => {}
        other => panic!("expected UnknownCoordinate, got {other:?}"),
    }
}

#[test]
fn rejects_overlapping_same_buffer_rows_on_write_path() {
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 2,
        pre_piece_next_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 0,
                    len_bytes: 20,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 5,
                    start_byte: 8,
                    len_bytes: 20,
                    tombstone: false,
                },
            },
        ],
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(5, 40)],
        pre_buffers_next_id: 6,
    };
    let env = envelope(vec![PieceTextEditItemManifest::Insert {
        at: BufferCoord {
            buffer_id: 5,
            byte_pos: 12,
        },
        inserted: manifest(4, 0xEE),
    }]);

    let err = run(pieces, buffers, &env).expect_err("must reject overlap");
    match err {
        PlannerError::SnapshotInvariant(msg) => {
            assert!(
                msg.contains("coord contradiction"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected SnapshotInvariant, got {other:?}"),
    }
}

// ---------- delete-position rejections / no-ops ----------

#[test]
fn rejects_delete_from_interior_to_document_start() {
    // Inverted range: delete starts inside a live piece and ends at
    // DOCUMENT_START. Canonicalization gives start = InRow{...}, end =
    // BeforeHead, so start > end. Must reject as InvalidEdit, not silently
    // no-op.
    let (pieces, buffers) = three_piece_doc_live();
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 2,
            byte_pos: 2,
        },
        end: BufferCoord::DOCUMENT_START,
    }]);
    let err = run(pieces, buffers, &env).expect_err("must reject");
    match err {
        PlannerError::InvalidEdit(msg) => {
            assert!(
                msg.contains("delete start resolved past delete end"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidEdit, got {other:?}"),
    }
}

#[test]
fn rejects_delete_with_start_clamped_past_tail_and_earlier_end() {
    // Tail of the chain is tombstoned, so a start coord landing on that
    // tombstoned tail forward-clamps to AfterTail. With end resolving to a
    // live position before AfterTail, start > end — must reject.
    //
    // Chain: A(live, buf 1, [0..2)) -> B(live, buf 2, [0..2)) -> C(tomb, buf 3, [0..3))
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 2,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 3,
                    start_byte: 0,
                    len_bytes: 3,
                    tombstone: true,
                },
            },
        ],
        pre_piece_next_id: 4,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(1, 2), buffer_meta(2, 2), buffer_meta(3, 3)],
        pre_buffers_next_id: 4,
    };
    // Start coord lands inside tombstoned C; DeleteStart forward-clamp runs
    // off the chain → AfterTail. End coord lands on live A (well before
    // AfterTail). Inverted: must reject.
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 3,
            byte_pos: 1,
        },
        end: BufferCoord {
            buffer_id: 1,
            byte_pos: 1,
        },
    }]);
    let err = run(pieces, buffers, &env).expect_err("must reject");
    match err {
        PlannerError::InvalidEdit(msg) => {
            assert!(
                msg.contains("delete start resolved past delete end"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidEdit, got {other:?}"),
    }
}

#[test]
fn zero_width_delete_at_inter_row_boundary_is_noop() {
    // start = right edge of A in chain; end = same boundary expressed as
    // left edge of A's chain-successor B. After canonicalization both
    // collapse to InRow{A, A.len}, so the delete is a no-op. The previous
    // implementation diverged because start and end normalised to different
    // (row, k) anchors and then position_eq said they were unequal.
    let (pieces, buffers) = three_piece_doc_live();
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        // start: right edge of piece 2 (buffer 2, len 4)
        start: BufferCoord {
            buffer_id: 2,
            byte_pos: 4,
        },
        // end: left edge of piece 3 (buffer 3, byte 0). 3 is the chain-next
        // of 2, so this is the same rendered byte gap.
        end: BufferCoord {
            buffer_id: 3,
            byte_pos: 0,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);
    assert!(out.piece_inserts.is_empty(), "no new pieces");
    assert!(out.piece_updates.is_empty(), "no row updates");
    assert!(out.buffer_inserts.is_empty(), "no buffer inserts");
    assert_eq!(out.head_update, None);
    assert_eq!(out.tail_update, None);
    assert_eq!(out.piece_next_id_post, None);
    assert_eq!(out.buffers_next_id_post, None);
}

#[test]
fn zero_width_delete_at_inter_row_boundary_with_tombstone_run_is_noop() {
    // chain: A(live, buf 1, [0..2)) -> T(tomb, buf 9, [0..3)) -> B(live, buf 2, [0..2))
    // Both `(buf 1, 2)` (right edge of A) and `(buf 2, 0)` (left edge of B)
    // refer to the same rendered byte gap because T renders nothing.
    // Canonicalization normalises both endpoints to InRow{A, A.len} (or to
    // InRow{A, A.len} via backward-clamp on (B, 0)). They must compare equal
    // and the delete must be a no-op.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 3,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 3,
                coord: PieceCoord {
                    buffer_id: 9,
                    start_byte: 0,
                    len_bytes: 3,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 3,
                list_number: LIST_NUMBER,
                prev_id: 2,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 2,
                    start_byte: 0,
                    len_bytes: 2,
                    tombstone: false,
                },
            },
        ],
        pre_piece_next_id: 4,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(1, 2), buffer_meta(9, 3), buffer_meta(2, 2)],
        pre_buffers_next_id: 10,
    };
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 1,
            byte_pos: 2,
        },
        end: BufferCoord {
            buffer_id: 2,
            byte_pos: 0,
        },
    }]);
    let out = run_unwrap(pieces, buffers, &env);
    assert!(out.piece_inserts.is_empty());
    assert!(out.piece_updates.is_empty());
    assert!(out.buffer_inserts.is_empty());
    assert_eq!(out.head_update, None);
    assert_eq!(out.tail_update, None);
}

#[test]
fn delete_inside_all_tombstoned_chain_is_noop() {
    // All-tombstoned chain: every row is tombstoned, so the rendered chain
    // is empty. A delete coord inside any tombstoned row's range
    // forward-clamps to AfterTail (DeleteStart) and back-clamps to
    // BeforeHead (DeleteEnd). With no live rows those two positions refer
    // to the same rendered byte gap (the empty document), so the delete
    // must be a no-op rather than an inverted-edit error.
    let pieces = PieceSnapshot {
        list_number: LIST_NUMBER,
        head_id: 1,
        tail_id: 2,
        pieces: vec![
            PieceRow {
                id: 1,
                list_number: LIST_NUMBER,
                prev_id: 0,
                next_id: 2,
                coord: PieceCoord {
                    buffer_id: 1,
                    start_byte: 0,
                    len_bytes: 3,
                    tombstone: true,
                },
            },
            PieceRow {
                id: 2,
                list_number: LIST_NUMBER,
                prev_id: 1,
                next_id: 0,
                coord: PieceCoord {
                    buffer_id: 2,
                    start_byte: 0,
                    len_bytes: 4,
                    tombstone: true,
                },
            },
        ],
        pre_piece_next_id: 3,
    };
    let buffers = BufferSnapshot {
        buffers: vec![buffer_meta(1, 3), buffer_meta(2, 4)],
        pre_buffers_next_id: 3,
    };
    // Start inside piece 1's tombstoned range; end inside piece 2's
    // tombstoned range. After clamping: start = AfterTail, end = BeforeHead.
    let env = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 1,
            byte_pos: 1,
        },
        end: BufferCoord {
            buffer_id: 2,
            byte_pos: 2,
        },
    }]);
    let out = run_unwrap(pieces.clone(), buffers.clone(), &env);
    assert!(out.piece_inserts.is_empty(), "no new pieces");
    assert!(out.piece_updates.is_empty(), "no row updates");
    assert!(out.buffer_inserts.is_empty(), "no buffer inserts");
    assert_eq!(out.head_update, None);
    assert_eq!(out.tail_update, None);
    assert_eq!(out.piece_next_id_post, None);
    assert_eq!(out.buffers_next_id_post, None);

    // Also verify the symmetric reversed-coordinate variant: start inside
    // piece 2 (clamps forward to AfterTail), end inside piece 1 (clamps
    // backward to BeforeHead) — same pair after canonicalization, still a
    // no-op (not an InvalidEdit despite ordinarily-inverted byte order).
    let env_swap = envelope(vec![PieceTextEditItemManifest::Delete {
        start: BufferCoord {
            buffer_id: 2,
            byte_pos: 1,
        },
        end: BufferCoord {
            buffer_id: 1,
            byte_pos: 2,
        },
    }]);
    let out_swap = run_unwrap(pieces, buffers, &env_swap);
    assert!(out_swap.piece_inserts.is_empty());
    assert!(out_swap.piece_updates.is_empty());
}

// ---------- random property tests (scalar oracle over UTF-32LE buffers) ----------

#[test]
fn random_insert_property_matches_string_oracle() {
    // Insert-only random test using a scalar (`char`) oracle that mirrors
    // §4.2's TextArea-API model. Buffers are UTF-32LE — every scalar is four
    // bytes — so a scalar index `n` maps to rendered byte offset `n * 4`, and a
    // payload of `k` scalars has `len_bytes = k * 4`. The planner runs, and we
    // compare the rendered chain (decoded from UTF-32LE) to the oracle string.
    use std::collections::HashMap;
    let seed = 0x1F00D_u64;
    let mut rng = LcgRng::new(seed);

    let mut oracle: Vec<char> = Vec::new();
    let mut buffer_contents: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut snapshot = empty_snapshot(1);
    let mut buffers = empty_buffers(1);

    // Cycle through a small palette of scalars to exercise UTF-32 boundaries
    // (BMP and astral). Single-byte ASCII is mixed in too.
    let palette: &[char] = &['a', 'b', 'c', '\u{00E9}', '\u{4E2D}', '\u{1F600}'];

    for round in 0..40 {
        let oracle_chars = oracle.len();
        let scalar_pos = if oracle_chars == 0 {
            0
        } else {
            (rng.next() as usize) % (oracle_chars + 1)
        };
        let payload_chars = 1 + (rng.next() as usize) % 3;
        let payload: Vec<char> = (0..payload_chars)
            .map(|_| palette[(rng.next() as usize) % palette.len()])
            .collect();
        let payload_utf32 = utf32le(&payload);
        let len_bytes = payload_utf32.len() as u32; // payload_chars * 4
        assert!(len_bytes > 0);

        let byte_pos = scalar_pos * 4;
        let at = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, byte_pos);
        let env = envelope(vec![PieceTextEditItemManifest::Insert {
            at,
            inserted: InsertedBufferManifest {
                len_bytes,
                ciphertext_len: len_bytes + 16,
                ciphertext_value_hash: [0xC1; 32],
            },
        }]);
        let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);

        oracle.splice(scalar_pos..scalar_pos, payload.iter().copied());

        let new_buffer_id = out.buffer_inserts[0].new_id;
        buffer_contents.insert(new_buffer_id, payload_utf32);
        apply_planner_output(&mut snapshot, &mut buffers, &out);

        let rendered = decode_utf32le(&render_chain(&snapshot, &buffer_contents));
        let expected: String = oracle.iter().collect();
        assert_eq!(rendered, expected, "oracle mismatch on round {round}");
    }
}

#[test]
fn random_insert_delete_property_matches_string_oracle() {
    use std::collections::HashMap;

    let seed = 0xABCDEF12_u64;
    let mut rng = LcgRng::new(seed);

    let mut oracle: Vec<char> = Vec::new();
    let mut buffer_contents: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut snapshot = empty_snapshot(1);
    let mut buffers = empty_buffers(1);

    let palette: &[char] = &['x', 'y', 'z', '\u{00F1}', '\u{2603}', '\u{1F4A1}'];

    // Seed with one insert so deletes have something to act on.
    {
        let payload: Vec<char> = "hello".chars().collect();
        let payload_utf32 = utf32le(&payload);
        let len_bytes = payload_utf32.len() as u32;
        let env = envelope(vec![PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: InsertedBufferManifest {
                len_bytes,
                ciphertext_len: len_bytes + 16,
                ciphertext_value_hash: [0; 32],
            },
        }]);
        let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
        oracle.splice(0..0, payload.iter().copied());
        buffer_contents.insert(out.buffer_inserts[0].new_id, payload_utf32);
        apply_planner_output(&mut snapshot, &mut buffers, &out);
    }

    for round in 0..50 {
        let oracle_chars = oracle.len();
        let do_insert = oracle_chars == 0 || !rng.next().is_multiple_of(3);
        if do_insert {
            let scalar_pos = (rng.next() as usize) % (oracle_chars + 1);
            let payload_chars = 1 + (rng.next() as usize) % 3;
            let payload: Vec<char> = (0..payload_chars)
                .map(|_| palette[(rng.next() as usize) % palette.len()])
                .collect();
            let payload_utf32 = utf32le(&payload);
            let len_bytes = payload_utf32.len() as u32;
            let at = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, scalar_pos * 4);
            let env = envelope(vec![PieceTextEditItemManifest::Insert {
                at,
                inserted: InsertedBufferManifest {
                    len_bytes,
                    ciphertext_len: len_bytes + 16,
                    ciphertext_value_hash: [0xAB; 32],
                },
            }]);
            let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
            oracle.splice(scalar_pos..scalar_pos, payload.iter().copied());
            buffer_contents.insert(out.buffer_inserts[0].new_id, payload_utf32);
            apply_planner_output(&mut snapshot, &mut buffers, &out);
        } else {
            let a = (rng.next() as usize) % (oracle_chars + 1);
            let b = (rng.next() as usize) % (oracle_chars + 1);
            let (s_chars, e_chars) = if a <= b { (a, b) } else { (b, a) };
            if s_chars == e_chars {
                continue;
            }
            // Scalar offsets map to UTF-32 byte offsets at 4 bytes per scalar.
            let start = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, s_chars * 4);
            let end = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, e_chars * 4);
            let env = envelope(vec![PieceTextEditItemManifest::Delete { start, end }]);
            let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
            oracle.drain(s_chars..e_chars);
            apply_planner_output(&mut snapshot, &mut buffers, &out);
        }
        let rendered = decode_utf32le(&render_chain(&snapshot, &buffer_contents));
        let expected: String = oracle.iter().collect();
        assert_eq!(rendered, expected, "oracle mismatch on round {round}");
    }
}

/// Encode a scalar sequence as UTF-32LE buffer bytes (4 bytes per scalar) —
/// the production buffer encoding the planner's byte coordinates index into.
fn utf32le(chars: &[char]) -> Vec<u8> {
    chars
        .iter()
        .flat_map(|c| (*c as u32).to_le_bytes())
        .collect()
}

/// Decode UTF-32LE buffer bytes back to a `String` (every 4 bytes is one
/// scalar). The oracles never split a scalar, so every chunk is a valid char.
fn decode_utf32le(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(4)
        .map(|c| {
            char::from_u32(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .expect("valid UTF-32 scalar")
        })
        .collect()
}

// ---------- random byte-oracle property tests (kept as additional coverage) ----------

#[test]
fn random_insert_property_matches_byte_oracle() {
    // Insert-only oracle: the rendered byte sequence (reading every live
    // piece in chain order, via its referenced buffer, by buffer-coord
    // start..start+len) should match a `Vec<u8>` we mutate in lockstep.
    // We stress same-coordinate inserts (newest-first) and split inserts.
    use std::collections::HashMap;
    let seed = 0xC0FFEE_u64;
    let mut rng = LcgRng::new(seed);

    let mut oracle: Vec<u8> = Vec::new();
    let mut buffer_contents: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut snapshot = empty_snapshot(1);
    let mut buffers = empty_buffers(1);

    for round in 0..30 {
        // `oracle_len` is always a multiple of 4; positions land on 4-byte
        // UTF-32 boundaries by picking a scalar slot, then multiplying by 4.
        let oracle_len = oracle.len();
        let pos = if oracle_len == 0 {
            0
        } else {
            ((rng.next() as usize) % (oracle_len / 4 + 1)) * 4
        };
        // Build a small inserted payload whose length is a whole number of
        // 4-byte UTF-32 units (the alignment the verifier enforces). The bytes
        // are arbitrary — this oracle checks byte-range splicing, not scalar
        // validity.
        let payload_len = (1 + (rng.next() as usize) % 4) * 4;
        let payload: Vec<u8> = (0..payload_len)
            .map(|_| (rng.next() as u8).wrapping_add(0x41))
            .collect();

        // Translate `pos` (rendered byte offset) to a BufferCoord.
        let at = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, pos);
        let env = envelope(vec![PieceTextEditItemManifest::Insert {
            at,
            inserted: InsertedBufferManifest {
                len_bytes: payload_len as u32,
                ciphertext_len: payload_len as u32 + 16,
                ciphertext_value_hash: [0xCC; 32],
            },
        }]);
        let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);

        // Update oracle.
        oracle.splice(pos..pos, payload.iter().copied());

        // Apply planner output to our local snapshot/buffers state for next
        // round.
        let new_buffer_id = out.buffer_inserts[0].new_id;
        buffer_contents.insert(new_buffer_id, payload.clone());

        apply_planner_output(&mut snapshot, &mut buffers, &out);

        // Compare rendered chain to oracle.
        let rendered = render_chain(&snapshot, &buffer_contents);
        assert_eq!(rendered, oracle, "oracle mismatch on round {round}");
    }
}

fn byte_offset_to_buffer_coord(
    snap: &PieceSnapshot,
    bufs: &std::collections::HashMap<i64, Vec<u8>>,
    pos: usize,
) -> BufferCoord {
    let _ = bufs;
    if snap.head_id == 0 {
        return BufferCoord::DOCUMENT_START;
    }
    // Always pick a coordinate that the planner will resolve to the *chain*
    // position the oracle has in mind, never one that aliases to a same-buffer
    // piece living elsewhere in the chain. Concretely:
    //   - interior of live row: byte coord inside that row
    //   - boundary between rows in chain order: predecessor's right edge
    //   - pos == 0 with no chain predecessor: DOCUMENT_START
    let mut consumed: usize = 0;
    let mut last_live: Option<&PieceRow> = None;
    let mut cursor = snap.head_id;
    while cursor != 0 {
        let row = snap.pieces.iter().find(|r| r.id == cursor).expect("row");
        if !row.coord.tombstone {
            let len = row.coord.len_bytes as usize;
            if pos == consumed {
                return match last_live {
                    None => BufferCoord::DOCUMENT_START,
                    Some(prev) => BufferCoord {
                        buffer_id: prev.coord.buffer_id,
                        byte_pos: prev.coord.start_byte + prev.coord.len_bytes,
                    },
                };
            }
            if pos > consumed && pos < consumed + len {
                let interior_offset = (pos - consumed) as u32;
                return BufferCoord {
                    buffer_id: row.coord.buffer_id,
                    byte_pos: row.coord.start_byte + interior_offset,
                };
            }
            consumed += len;
            last_live = Some(row);
        }
        cursor = row.next_id;
    }
    match last_live {
        Some(prev) => BufferCoord {
            buffer_id: prev.coord.buffer_id,
            byte_pos: prev.coord.start_byte + prev.coord.len_bytes,
        },
        None => BufferCoord::DOCUMENT_START,
    }
}

fn render_chain(snap: &PieceSnapshot, bufs: &std::collections::HashMap<i64, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = snap.head_id;
    while cursor != 0 {
        let row = snap.pieces.iter().find(|r| r.id == cursor).expect("row");
        if !row.coord.tombstone {
            let buf = bufs.get(&row.coord.buffer_id).expect("buf in test map");
            let start = row.coord.start_byte as usize;
            let end = start + row.coord.len_bytes as usize;
            out.extend_from_slice(&buf[start..end]);
        }
        cursor = row.next_id;
    }
    out
}

fn apply_planner_output(snap: &mut PieceSnapshot, bufs: &mut BufferSnapshot, out: &PlannerOutput) {
    use std::collections::HashMap;

    let mut by_id: HashMap<i64, PieceRow> =
        snap.pieces.iter().cloned().map(|r| (r.id, r)).collect();
    for ins in &out.piece_inserts {
        by_id.insert(
            ins.new_id,
            PieceRow {
                id: ins.new_id,
                list_number: ins.list_number,
                prev_id: ins.prev_id,
                next_id: ins.next_id,
                coord: ins.coord,
            },
        );
    }
    for upd in &out.piece_updates {
        let row = by_id.get_mut(&upd.id).expect("update target row");
        if let Some(p) = upd.prev_id {
            row.prev_id = p;
        }
        if let Some(n) = upd.next_id {
            row.next_id = n;
        }
        if let Some(c) = upd.coord {
            row.coord = c;
        }
    }
    snap.pieces = by_id.into_values().collect();
    snap.pieces.sort_by_key(|r| r.id);
    if let Some(h) = out.head_update {
        snap.head_id = h;
    }
    if let Some(t) = out.tail_update {
        snap.tail_id = t;
    }
    if let Some(p) = out.piece_next_id_post {
        snap.pre_piece_next_id = p;
    }
    if let Some(p) = out.buffers_next_id_post {
        bufs.pre_buffers_next_id = p;
    }
    for bi in &out.buffer_inserts {
        bufs.buffers.push(BufferMeta {
            id: bi.new_id,
            owner_table: bi.owner_table.clone(),
            owner_row_id: bi.owner_row_id,
            owner_column: bi.owner_column.clone(),
            author_id: bi.author_id,
            len_bytes: bi.len_bytes,
        });
    }
}

struct LcgRng(u64);
impl LcgRng {
    fn new(seed: u64) -> Self {
        LcgRng(seed)
    }
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
}

#[test]
fn random_insert_delete_property_matches_byte_oracle() {
    use std::collections::HashMap;

    let seed = 0xDEADBEEF_u64;
    let mut rng = LcgRng::new(seed);

    let mut oracle: Vec<u8> = Vec::new();
    let mut buffer_contents: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut snapshot = empty_snapshot(1);
    let mut buffers = empty_buffers(1);

    // Seed with one insert so deletes have something to act on (8 bytes = two
    // 4-byte UTF-32 units).
    {
        let payload = b"hellobye".to_vec();
        let env = envelope(vec![PieceTextEditItemManifest::Insert {
            at: BufferCoord::DOCUMENT_START,
            inserted: InsertedBufferManifest {
                len_bytes: payload.len() as u32,
                ciphertext_len: payload.len() as u32 + 16,
                ciphertext_value_hash: [0; 32],
            },
        }]);
        let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
        oracle.splice(0..0, payload.iter().copied());
        buffer_contents.insert(out.buffer_inserts[0].new_id, payload);
        apply_planner_output(&mut snapshot, &mut buffers, &out);
    }

    for _round in 0..40 {
        let do_insert = oracle.is_empty() || !rng.next().is_multiple_of(3);
        if do_insert {
            // Positions and lengths stay on 4-byte UTF-32 boundaries.
            let pos = ((rng.next() as usize) % (oracle.len() / 4 + 1)) * 4;
            let payload_len = (1 + (rng.next() as usize) % 3) * 4;
            let payload: Vec<u8> = (0..payload_len)
                .map(|_| (rng.next() as u8).wrapping_add(0x21))
                .collect();
            let at = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, pos);
            let env = envelope(vec![PieceTextEditItemManifest::Insert {
                at,
                inserted: InsertedBufferManifest {
                    len_bytes: payload_len as u32,
                    ciphertext_len: payload_len as u32 + 16,
                    ciphertext_value_hash: [0xAB; 32],
                },
            }]);
            let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
            oracle.splice(pos..pos, payload.iter().copied());
            buffer_contents.insert(out.buffer_inserts[0].new_id, payload);
            apply_planner_output(&mut snapshot, &mut buffers, &out);
        } else {
            let slots = oracle.len() / 4;
            let a = ((rng.next() as usize) % (slots + 1)) * 4;
            let b = ((rng.next() as usize) % (slots + 1)) * 4;
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            if start == end {
                continue;
            }
            let start_coord = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, start);
            let end_coord = byte_offset_to_buffer_coord(&snapshot, &buffer_contents, end);
            let env = envelope(vec![PieceTextEditItemManifest::Delete {
                start: start_coord,
                end: end_coord,
            }]);
            let out = run_unwrap(snapshot.clone(), buffers.clone(), &env);
            oracle.splice(start..end, std::iter::empty::<u8>());
            apply_planner_output(&mut snapshot, &mut buffers, &out);
        }
        let rendered = render_chain(&snapshot, &buffer_contents);
        assert_eq!(rendered, oracle, "oracle mismatch");
    }
}
