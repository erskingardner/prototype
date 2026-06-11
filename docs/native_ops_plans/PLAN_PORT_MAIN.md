# PLAN — Forward-port the native-ops framework onto `main` (old storage)

Agent-executable. Sibling of `PLAN_PORT_MRT.md`: the **same** native-ops framework,
onto `main` instead of `trev/mrt`. Each stage has one runnable **gate**; one commit
per stage; every stage independently green.

> **This is the easy target — a forward-port, not a re-port.** `main` is on the
> *same storage* as the reference: `OpVerifyResult.write_steps: Vec<TraceStep>` and
> the old `create_trace` / `PrunedMerkleTree` / `encode_pruned_compact` trace API. So
> the native-ops code already compiles against this storage — most of it lands as
> **net-new files dropped in verbatim** from the reference. There is **no** storage
> adaptation: no MRT `§1` rules, no `--features mrt`, no proof-seam rewrite. The only
> real work is reconciling **9 shared files** against main's SDK-API churn since #209.

This plan is **Phase A only** — the native-ops framework + chat & table-fs verifiers
+ harnesses + native bench. Tree-fs is out of scope here (that's `PLAN_PORT_MRT.md`
Phase B / a later main pass).

---

## 0. Start point & reference

**Base: `origin/main`** (currently `#231`, `fdab33cc`; old storage). **Not** `trev/mrt`.

**Reference (port *from*): `trev/native-ops-tree-fs`** — local bookmark in this repo,
tip `925d9d1d`, built on old storage at `#209`. Read it with
`jj file show -r trev/native-ops-tree-fs <path>`. Its **native-ops portion is
`759cf1e5..59aa9db9`** (everything *below* the tree-fs `T0..T5` commits) — that is the
scope. Exclude tree-fs.

The reference commit map (bottom→top): `Stage 1` (enum/keys) → `Stage 2` (native op +
dispatch) → `Stage 3..5` + `B1..B3` (differential harness + proof seam) → per-op
rollout `Stage 2..12` + `create_channel` → self-consistency suites. View it:
`jj log -r '759cf1e5..59aa9db9'`.

### Setup
```
jj git fetch
jj new main@origin                       # start on top of current main
jj bookmark create trev/native-ops-main  # the branch
```

### Conventions (apply to every gate)
- A filtered `cargo test` is green **only if Cargo reports the intended tests ran**.
  `0 tests` is a **failure**, even on exit 0.
- `RISC0_SKIP_BUILD=1` for stages that don't prove; **proof stages (M2, M4b) use
  `RISC0_DEV_MODE=1` and never `RISC0_SKIP_BUILD`** — the proof test self-skips when it
  is set (a skipped proof is a failed gate). *(No `--features mrt` anywhere — that flag
  does not exist on `main`; this is the default/old-storage build.)*
- **Port the reference tip's *final state*, not a commit replay.** The log is an
  inventory; replaying intermediate commits re-introduces bugs later hardened away
  (`2c57e308`, `ae924192`). Diff/translate each unit against `trev/native-ops-tree-fs`.
- Lint gate (CI command, before each stage commit):
  ```
  RISC0_SKIP_BUILD=1 cargo clippy --workspace --exclude encrypted-spaces-ffi --all-targets --locked -- -D warnings
  ```
- End each stage with `jj commit -m '<the stage subject below>'`. Keep stages separate;
  don't squash. Publish: `jj bookmark set trev/native-ops-main -r @-` then
  `jj git push --bookmark trev/native-ops-main --allow-new`.

---

## 1. The only thing to reconcile — main's SDK-API delta since #209

main is 7 commits over `#209`; native-ops overlaps just **9 files**. Everything else
in native-ops is net-new and lands verbatim. The verifiers (`native_ops.rs`), dispatch
(`ops/mod.rs`), and the proof seam are **not** in the conflict set — main didn't touch
them — so they port clean. Reconcile these against the named PRs:

| shared file | reconcile against |
|---|---|
| `sdk/src/lib.rs` | `#231` *(remove unused public methods + re-exports)* — native-ops adds `submit_*_native` + native-op type re-exports; merge with #231's re-export cleanup |
| `sdk/src/local_transport.rs` | `#229` *(AuthContext made internal; `Space::uid()`)* |
| `demos/tauri/test-harness/src/world.rs` | `#229` *(uid / AuthContext surface)* |
| `demos/tauri/src-tauri/src/chat.rs` | `#211` *(unify `table.insert` with select/delete/update)* |
| `ffproof/integration_tests/benches/ffchat_cycle_benchmarks.rs` · `ff_cycle_benchmarks.rs` · `action_cycle_benchmarks.rs` · `ff_common/mod.rs` | main's bench evolution — **same reconciliation as the mrt `#209` merge**: adopt main's harness as the base, re-graft the native bench rows on top |
| `.github/workflows/build-prototype.yml` | trivial CI conflict |

(The 3 SDK PRs to read: `5abcecf9` #211, `09aee365` #229, `fdab33cc` #231.)

**Mechanism:** bring the reference's native-ops over — net-new files copy in as-is;
only the 9 above need hand-merging. You may `jj rebase` the `759cf1e5..59aa9db9`
prefix onto `main@origin` and resolve, or re-apply by layer per the stages below.
Either way, gate at each stage.

---

## Stage M0 — Baseline
**Goal:** branch off main; confirm it builds and note the SDK delta you'll hit (§1).
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo check -p encrypted-spaces-changelog-core
RISC0_SKIP_BUILD=1 cargo test  -p encrypted-spaces-changelog-core --lib
```
Pass = both succeed; the test reports >0 tests. **Commit** `M0 — baseline (main <SHA>)`.

## Stage M1 — Native-op framework + dispatch (ops stubbed)
**Goal:** the `NativeOp` verifier exists and is registered; every op rejects.
**Source:** reference `Stage 1` (`45b32851`, enum + keys) + `Stage 2` (`27d33095`,
`native_ops.rs` + dispatch — borrow shape, stub/reject handlers) + `B1` (`030ce0e5`,
`sdk/src/native_op.rs` submit + server wiring). Net-new files drop in; **reconcile
`sdk/src/lib.rs` (#231 re-exports) and `sdk/src/local_transport.rs` (#229)**.
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo check -p encrypted-spaces-changelog-core -p encrypted-spaces-sdk
RISC0_SKIP_BUILD=1 cargo test  -p encrypted-spaces-changelog-core native_op
```
Pass = compiles; a "native op rejected / dispatch" test runs and passes (>0).
**Commit** `M1 — native-op framework + dispatch`.

## Stage M2 — Proof seam (verify — **not** a rewrite)
**Goal:** the existing FF-proof native test passes on main. Old storage = the
reference's proof seam already targets this trace API; nothing to rewrite. Only risk:
`#229`/`#231` SDK churn reaching the transport/prover surface the test uses.
**Source:** reference `B2`/`B3` land verbatim.
**Gate — must actually prove; do NOT set `RISC0_SKIP_BUILD`:**
```
RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-ff-test --test integration_tests \
  test_native_update_message_in_ff_proof_batch -- --nocapture
```
Pass = runs to completion and passes. **FAILURE** if output contains
`Skipping … RISC0_SKIP_BUILD is set` or reports 0 tests. **Commit** `M2 — native proof seam`.

## Stage M3 — Per-op verifiers (chat + table-fs)
**Goal:** all 13 verifiers ported (update/send/delete message; add/delete reaction;
add_attachment; create_channel; update_channel_description; set_user_name; add_inode;
rename_inode; move_inode; delete_inode_recursive).
**Source:** port the **final state** of each at the reference tip — inventory only from
the log: `update_message` (foundation) + rollout `Stage 2..12` + `create_channel`
(`4a913afe` / merge `22e02930`). Confirm all 13 by grepping the tip's `native_ops.rs`
dispatch. *(No write-order / §1 concerns — same storage.)*
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-changelog-core native_ops
```
Pass = native↔data-driven differential tests run and pass (>0). Do ops incrementally.
**Commit(s)** `M3 — <op> verifier`.

## Stage M4 — Self-consistency harnesses
**Goal:** fs + chat consistency suites pass in both `Wrapper` and `Native` modes.
**Source:** reference `a08a15ad`, `74e2684f`, `c0901cf7`, `59aa9db9`
(`test-harness/tests/{fs,chat}_consistency.rs`, `fs_test_model.rs`, `chat_test_model.rs`).
**Reconcile** `test-harness/src/world.rs` (#229) and `demos/tauri/src-tauri/src/chat.rs` (#211).
**Gate:**
```
cargo test -p encrypted-spaces-demo-test-harness --test fs_consistency
cargo test -p encrypted-spaces-demo-test-harness --test chat_consistency
```
Pass = both binaries run; output includes the `*_native_writes` cases. **Commit**
`M4 — self-consistency harnesses`.

## Stage M4b — Native benchmark rows *(closes the framework)*
**Goal:** the `fs_*_native` + chat-native cases emit cycle rows beside the data-driven
rows. **Reconcile the 4 bench files** (adopt main's harness, re-graft the native rows —
same shape as the mrt `#209` merge).
**Source:** reference `e4074cb1` ("bench: add native ffchat cases").
**Gate (proves — `RISC0_DEV_MODE=1`):**
```
RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --bench ffchat_cycle_benchmarks -- fs_file_insert_native
```
Pass = output includes the `fs_file_insert_native` row (and the other `*_native` rows).
**Commit** `M4b — native benchmark rows`.

**▶ Done** — `trev/native-ops-main` carries the native-ops framework on mainline
storage. Land/PR it independently of the MRT migration.

---

## Risk & sequencing notes
- **Much lower risk than the mrt port** — no proof-seam rewrite (M2 is a *verification*,
  not a long pole). The only fiddly bit is the bench reconciliation (M4b) and the
  `sdk/src/lib.rs` re-export merge (M1).
- **Shares the storage-agnostic ~80% with `PLAN_PORT_MRT.md` Phase A** — the verifier
  logic, dispatch, `submit_*_native`, and harnesses are *identical code* on both
  storages. Author/port them once; the two branches diverge only in the storage seam.
- **Relationship to MRT:** since `trev/mrt` is "main + MRT storage port," once native-ops
  is on main, a future `trev/mrt` re-sync onto main carries it along (translating the
  seam to MRT = `PLAN_PORT_MRT.md` Phase A's P2). If you need it on mrt sooner, run that
  plan in parallel. When the storage migration lands, the two converge.
- If `origin/main` advances mid-port, `jj git fetch` then `jj rebase -b @ -d main@origin`
  and re-run the **M0** gate.
