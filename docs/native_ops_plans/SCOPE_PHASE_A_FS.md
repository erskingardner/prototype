# Scope: Phase A — Filesystem slice only (no chat)

This branch (`trev/native-ops-mrt`) deliberately implements the **Filesystem
slice** of Phase A from [`PLAN_PORT_MRT.md`](PLAN_PORT_MRT.md), **not** the full
Phase A. This is an intentional re-scope, recorded here so the gaps below read
as decisions rather than unfinished stages.

## Implemented

- **P2** — proof seam + native-op server-accept (in full).
- **P3 (FS)** — the four inode verifiers: `add_inode`, `rename_inode`,
  `move_inode`, `delete_inode_recursive` (+ `update_message` as the dispatch
  template).
- **P4 (FS)** — the `fs_consistency` self-consistency suite (Wrapper + Native).
- **P4b (FS)** — `fs_file_insert_native` / `fs_file_delete_native` benchmark
  rows.

## Intentionally NOT implemented (deviations from the plan)

The plan's Phase A also covers a **chat** half and broader bench coverage; this
branch omits all of it by design:

- **P3 chat** — the 8 chat/user verifiers (`send_message`, `delete_message`,
  add/delete `reaction`, `add_attachment`, `create_channel`,
  `update_channel_description`, `set_user_name`).
- **P4 chat** — `chat_consistency.rs` + `chat_test_model.rs` (the gate at
  `PLAN_PORT_MRT.md:233` expects both `fs_consistency` *and* `chat_consistency`;
  only the former is present).
- **P4b chat** — chat-native benchmark rows (`CHAT_CASES` remain data-driven
  only).
- **P4b directory-native** — `fs_directory_*_native` rows. P4b ports only the
  reference's file-native cases (`e4074cb1`), so the FS-native bench is
  `fs_file_*_native`, not all `fs_*_native`.
- **Phase B (tree-fs, P5–P7)** — a separate phase/branch; not started.

## Gate status (FS slice)

- **P4:** `cargo test -p encrypted-spaces-demo-test-harness --features mrt --test fs_consistency`
  — 12 pass, incl. all 5 `*_native_writes` cases.
- **P4b:** `RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --features mrt --bench ffchat_cycle_benchmarks -- fs_file_insert_native`
  — emits the native row.

## What the FS consistency suite asserts (precise claim)

Observable **read-surface** equivalence — listings/fields, bytes round-trip,
ordering, absence, reachability — between the data-driven and native write
paths, checked against an independent in-memory model
([`fs_test_model.rs`](../../demos/tauri/src-tauri/src/fs_test_model.rs)). It is
**not** raw committed-state / byte-level equality: it catches drift the read
surface exposes, not byte-level KV differences invisible to reads.
