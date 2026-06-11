# PLAN_PIECE_SMALL_CLEANUP.md

Goal: make `PieceTextEditOp` use indexed `OpReader` coordinate resolution
instead of reading the whole `_piecetext_pieces` list for the target document.

This plan intentionally keeps the implementation small by **not** adding
per-document piece counters. That means this change removes the current
document-level all-piece/live-piece cap enforcement from `PieceTextEditOp`.
Keep the per-edit envelope/body/insert limits.

## Scope

Keep:

- `_piecetext_pieces.buffer_id` column and index.
- `PieceTextEdit` envelope, op type, wire format, and SDK API.
- cleanup ops and buffer cleanup orphan detection as-is.
- per-edit limits: max ops, inserted buffers, envelope bytes, body bytes,
  inserted buffer bytes.

Change:

- `PieceTextEditOp::extract_and_validate` must no longer call
  `read_piece_snapshot()` or range-read `_piecetext_pieces.list_number` to plan
  an edit.
- Edit planning must resolve `BufferCoord`s through the indexed `OpReader`
  path, with an overlay for writes staged earlier in the same edit.
- Remove or rewrite docs/tests/metrics that claim `PieceTextEditOp`
  authenticates the full document piece list.

Do not do:

- No `_piecetext_buffers.refcount`.
- No removal of `_piecetext_pieces.buffer_id` index.
- No per-document piece/live counters in this pass.
- No TextArea / shared-notes UI changes.

## Key Design

Introduce one production indexed planner:

```text
PieceTextEditOp
  -> IndexedPieceEditPlanner
     -> OverlayPieceStore
        -> OpReader fallback reads
```

`OverlayPieceStore` must:

- read pre-state candidate rows through `_piecetext_pieces.buffer_id`;
- read head/tail/next-id keys;
- point-read rows by id as needed;
- cache reads so the same row/key is not repeatedly authenticated;
- stage row inserts, row updates, head/tail updates, and next-id updates;
- merge pre-state candidate row ids with staged new rows for the same buffer;
- return staged versions of pre-existing rows after they are updated;
- materialize the same `_piecetext_pieces` / `_piecetext_buffers` writes that
  the current planner emits.

The planner must preserve multi-op edit semantics: later ops in the same
`PieceTextEdit` resolve against earlier staged changes.

## Stage 0 - Baseline And Guard Test

Add a focused test that proves the final behavior expected from this plan:

- A `PieceTextEdit` over a large document must not perform a range read over
  `_piecetext_pieces.list_number`.
- The test should inspect `ReadOp`s from a stub/prover reader.
- It should fail on the current full-snapshot implementation.

Suggested test name:

```text
piece_text_edit_op_uses_indexed_coord_reads_not_full_list_snapshot
```

Gate:

```text
cargo test -p encrypted-spaces-changelog-core piece_text_edit_op_uses_indexed_coord_reads_not_full_list_snapshot
```

Expected before later stages: fails for the right reason. Do not leave the
branch in this state unless the next stage is implemented in the same commit.

## Stage 1 - Build The Indexed Overlay Store

Add a new internal module, or equivalent local structure, for indexed edit
planning. Prefer a focused module over expanding `piece_text_edit_op.rs`.

Required API shape:

```text
IndexedPieceEditPlanner::new(reader, address, list_number, author_id, head_id, tail_id, ...)
IndexedPieceEditPlanner::apply_ops(envelope.edit.ops)
IndexedPieceEditPlanner::into_output()
```

The planner output can either reuse `PlannerOutput` or use a new output type
with the same materialization information:

- piece inserts
- piece updates
- buffer inserts
- head/tail updates
- piece/buffer next-id updates
- trace/metrics useful for tests

Implement store primitives first:

- `read_piece_row(row_id)`
- `candidate_row_ids(buffer_id)` using `_piecetext_pieces.buffer_id`
- `read_head()` / `read_tail()`
- `set_prev`, `set_next`, `set_coord`
- `insert_new_row`
- `alloc_piece_id`
- `alloc_buffer_id`

Local checks for every row read:

- positive row id
- correct `list_number`
- valid `prev_id` / `next_id` shape when used in a walk
- nonzero `len_bytes`
- UTF-32 alignment
- range overflow rejection

Gate:

```text
cargo test -p encrypted-spaces-changelog-core piece_text
cargo fmt -p encrypted-spaces-changelog-core -- --check
```

At the end of this stage, production `PieceTextEditOp` may still use the old
snapshot planner. This stage is allowed to be behavior-neutral.

## Stage 2 - Port Insert Planning

Implement indexed insert planning against the overlay:

- resolve `Insert.at` through `resolve_coord_core`;
- `resolve_coord_core` must verify the candidate rows for a buffer are disjoint;
- derive insert splice:
  - at head,
  - after row,
  - split row;
- insert new buffer metadata and contents hash writes;
- stage piece row changes in the overlay;
- update head/tail and next-id state.

Important: preserve same-coordinate insert ordering. Multiple inserts at the
same coordinate in one edit must still render newest-first/LIFO.

Add tests mirroring existing planner tests against `PieceTextEditOp`, not just
the pure planner:

- empty insert into empty document;
- append after existing piece;
- split insert inside a piece;
- same-coordinate inserts render newest-first;
- insert inside tombstone back-clamps to live predecessor;
- insert after a row changed earlier in the same edit.

Gate:

```text
cargo test -p encrypted-spaces-changelog-core piece_text_edit_op
cargo test -p encrypted-spaces-changelog-core piece_text_planner::tests::same_coordinate_inserts_render_newest_first
```

## Stage 3 - Port Delete Planning

Implement indexed delete planning against the overlay:

- resolve `Delete.start` and `Delete.end` through `resolve_coord_core`;
- canonicalize delete endpoints using overlay row reads;
- walk only the affected `next_id` span;
- validate pointer symmetry while walking;
- split/tombstone affected rows using the same semantics as the current planner;
- reject inverted ranges;
- no-op zero-width deletes.

The delete span walk is allowed to be proportional to deleted/touched rows. It
must not scan untouched rows outside the affected span.

Add tests against `PieceTextEditOp`:

- whole-piece delete only flips tombstone;
- ragged left/center/right delete within one piece;
- delete across multiple pieces;
- overlapping sequential deletes are idempotent in overlap;
- delete then insert at deleted boundary;
- delete inside all-tombstoned chain is no-op;
- start/end clamping through tombstone runs;
- inverted range rejection.

Gate:

```text
cargo test -p encrypted-spaces-changelog-core piece_text_edit_op
cargo test -p encrypted-spaces-changelog-core piece_text_planner
```

## Stage 4 - Switch `PieceTextEditOp`

Replace the production path in `PieceTextEditOp::extract_and_validate`:

Remove:

- `read_piece_snapshot(...)`
- `read_piece_row_ids_for_list(...)`
- all use of `_piecetext_pieces.list_number` as a full document snapshot read
  for edit planning
- `enforce_document_piece_caps(...)`
- tests whose only purpose is all-row/live-row cap enforcement

Keep:

- parent cell/list-number validation;
- ACL checks;
- inserted body/hash validation;
- buffer owner/address validation for every existing buffer read;
- materialized write key uniqueness checks;
- per-edit envelope/body limits.

Update `PieceTextEditExecutionMetrics`:

- rename or redefine `piece_rows_read` as touched/authenticated piece rows;
- remove `live_piece_rows` / `tombstone_piece_rows` if they implied full
  document counts;
- keep inserted/updated/write counts if useful.

Update docs in `piece_text.rs` and comments in `piece_text_edit_op.rs` so they
no longer claim the edit verifier reads the whole document or enforces
`MAX_PIECETEXT_*_PER_DOCUMENT`.

Mechanical grep gate:

```text
if rg "read_piece_snapshot|read_piece_row_ids_for_list|enforce_document_piece_caps" ffproof/changelog_core/src/ops/piece_text_edit_op.rs; then exit 1; fi
if rg "authenticates the full|whole-document proof cost|MAX_PIECETEXT_PIECES_PER_DOCUMENT|MAX_PIECETEXT_LIVE_PIECES_PER_DOCUMENT" ffproof/changelog_core/src/piece_text.rs ffproof/changelog_core/src/ops/piece_text_edit_op.rs; then exit 1; fi
```

Functional gate:

```text
cargo test -p encrypted-spaces-changelog-core piece_text
cargo fmt -p encrypted-spaces-changelog-core -- --check
```

## Stage 5 - Reconcile Or Retire The Old Snapshot Planner

After `PieceTextEditOp` uses the indexed overlay planner, decide what remains
of `piece_text_planner.rs`.

Preferred end state:

- one algorithm, two storage adapters:
  - `OpReader` overlay adapter for production verifier/proof/guest;
  - in-memory adapter for property tests/fuzz/model checks.

Acceptable smaller end state:

- keep the old pure planner only for tests/fuzz for now;
- production path must not call it;
- add comments naming it as a model/test planner.

Do not keep two production edit planners.

Gate:

```text
rg -n "plan_edit\\(" ffproof/changelog_core/src sdk/tests
```

Expected after this stage:

- no production call from `piece_text_edit_op.rs` to `plan_edit`;
- test/fuzz callers are okay if intentionally kept.

## Stage 6 - SDK And FF Validation

Run the SDK PieceText tests that exercise real submit/verify/apply behavior:

```text
RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-sdk --features local-transport --test piece_text_two_client
RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-sdk --features local-transport piecetext::tests::local_api_tests::
RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 FUZZ_ITERS=200 cargo test -p encrypted-spaces-sdk --test piece_text_concurrency_stress fuzz_piecetext -- --ignored
```

Run a proof/FF smoke gate that includes `PieceTextEdit` changes. Use the
smallest existing targeted test that covers PieceText in the FF/prover path; if
there is no targeted test, add one before claiming this stage complete.

Suggested command if still present:

```text
RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-ffproof piece_text -- --nocapture
```

If that filter does not run a PieceText proof test, add a targeted one and use
its exact name here.

## Stage 7 - Final Quality Gate

Run:

```text
cargo fmt -p encrypted-spaces-changelog-core -p encrypted-spaces-sdk -- --check
RISC0_SKIP_BUILD=1 cargo clippy -p encrypted-spaces-changelog-core --all-targets --locked -- -D warnings
RISC0_SKIP_BUILD=1 cargo clippy -p encrypted-spaces-sdk --all-targets --features local-transport --locked -- -D warnings
cargo test -p encrypted-spaces-changelog-core piece_text
RISC0_SKIP_BUILD=1 RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-sdk --features local-transport --test piece_text_two_client
```

Record in the final response:

- whether `PieceTextEditOp` still performs any `_piecetext_pieces.list_number`
  range read;
- the exact tests run;
- any remaining full-scan behavior outside `PieceTextEditOp` such as cleanup.

## Risks To Call Out

- Removing document-level piece caps removes the current global DoS bound for a
  single PieceText document. Per-edit limits still bound each edit, but repeated
  edits can grow piece rows until cleanup/storage/proof costs become operational
  issues.
- Delete planning must be careful with overlay state. Later ops in the same edit
  must see earlier staged tombstones/splits/head-tail changes.
- The `_piecetext_pieces.buffer_id` index only finds rows by buffer. Delete
  execution still needs chain walking by `next_id` across the affected span.
- Any metric/doc text that still says "whole-document proof cost" after this
  change is stale and should block completion.
