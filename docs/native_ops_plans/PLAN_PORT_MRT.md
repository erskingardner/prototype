# PLAN — Port native-ops + tree-fs onto the MRT/AVL storage (`trev/mrt`)

Agent-executable. Each stage has one runnable **gate**; do not advance until it is
green. Work stage-by-stage, one commit per stage, every stage independently
buildable and tested.

> **Two stacked phases.** **Phase A** ports the native-ops *framework* + the chat and
> table-fs verifiers (P0–P4b) onto MRT — self-contained, no tree-fs, no UI change, and
> independently mergeable. **Phase B** stacks tree-fs on top (P5–P7). Branches:
> `trev/native-ops-mrt` (A) → `trev/tree-fs-mrt` (B, off A's tip). Same `native_ops.rs`
> dispatch throughout — Phase B just adds tree-fs match arms + the codec.

---

## 0. Where you start, and how to find the reference

**Base branch (start here): `origin/trev/mrt`.**
Do **not** start from `main`. `origin/main` (`#231`) does **not** contain the
AVL/MRT storage port; none of this plan applies there. Everything below assumes
the MRT storage rewrite that lives only on `trev/mrt`.

`trev/mrt` is **force-pushed** (history is rewritten as the port lands fixes).
Pin to the exact tip you branched from and record it; if it moves under you,
re-base deliberately and re-run the P0 gate — never assume an old `trev/mrt` SHA
still exists.

**Reference branch (port *from*): `trev/native-ops-tree-fs`** (local bookmark in
this repo, tip `925d9d1d`). The finished implementation on the old storage; you
translate it onto MRT. Read-only source material — never merge or cherry-pick it
wholesale (it is built against the *old* trace/witness API; see the adaptation rules).

> **No push required.** The agent runs **in this same jjco repo**, where
> `trev/native-ops-tree-fs` is already a local bookmark and `trev/mrt@origin` is
> already fetched — everything is in the local object store. Push this **source**
> bookmark only to make it fetchable from a *different* clone, or to back up the
> unpushed reference: `jj git push --bookmark trev/native-ops-tree-fs --allow-new`.
> (To publish or PR the **port work**, push `trev/native-ops-mrt` instead — see
> Conventions; never push the source bookmark for that.)

How the agent reads the reference (local bookmark — no `@origin` needed):
```
jj file show -r trev/native-ops-tree-fs ffproof/changelog_core/src/native_ops.rs
jj file show -r trev/native-ops-tree-fs ffproof/changelog_core/src/tree_fs.rs
jj diff --from 759cf1e5 --to trev/native-ops-tree-fs <path>     # 759cf1e5 = #209, the shared base
```
The reference's commit log is the porting map (bottom→top) — `jj log -r
'759cf1e5..trev/native-ops-tree-fs'`: `Stage 1..13` = native-op framework + per-op
verifiers; `B1..B3` = proof seam; `T0..T5` = tree-fs. Skip the bottom `#209`
benchmark commits — already in `trev/mrt`.

### Setup commands (agent)
Bookmarks are jj's branches; they do **not** auto-follow your working commit — set
them explicitly before pushing. Working in-place is clean even though this checkout
is mid-mess: `jj new` starts a fresh commit on top of `trev/mrt`, ignoring the
current working state.
```
# Phase A starts here; Phase B branches off Phase A's tip (see the Phase B header).
jj git fetch                                # refresh trev/mrt@origin (it is force-pushed; get the latest)
jj new trev/mrt@origin                      # start Phase A on top of the MRT tip
jj bookmark create trev/native-ops-mrt      # Phase A branch
# record base SHA for the P0 description: jj log -r trev/mrt@origin --no-graph -T commit_id
```

### Conventions (apply to every gate)
- A filtered `cargo test` is green **only if Cargo reports the intended tests ran**.
  `0 tests` (or fewer than the named tests) is a **failure**, even on exit 0.
- **Enable `--features mrt` on EVERY build / test / lint / bench — it is not a
  default feature.** Without it, `ffproof_tracer_shared` resolves
  `backend = merk::avl` (`tracer/shared/src/lib.rs:4-7`), so the gate validates the
  **AVL** path, not the MRT port — it can pass while exercising the wrong backend.
  The feature propagates through `encrypted-spaces-{ff-test,sdk,backend,changelog-core}`.
  **`encrypted-spaces-demo` and the test-harness define no `mrt` feature** — P4/P5/P6 must
  first add an `mrt` passthrough to their `Cargo.toml`
  (`mrt = ["encrypted-spaces-sdk/mrt", "encrypted-spaces-changelog-core/mrt"]`) before their
  gates can enable it. Sanity that you are really on MRT: genesis
  `INITIAL_INTERNAL_DATA_COMMITMENT_HEX` is the MRT value `0fca009d…`, not AVL `7ac1d1e9…`.
- Prefix cargo with `RISC0_SKIP_BUILD=1` (matches CI; avoids rebuilding the zkVM
  guest) **only for stages that don't prove**. Proof stages (P2, P4b, P7) must run the
  guest — use `RISC0_DEV_MODE=1` and **never** `RISC0_SKIP_BUILD`, because the
  proof tests self-skip when it is set (a skipped proof is a failed gate, not a pass).
- **Port the reference tip's *final state*, not a commit replay.** Use the commit
  log as an inventory/map only; replaying intermediate commits re-introduces bugs
  later hardened away. Diff/translate each unit against `trev/native-ops-tree-fs`.
- Lint gate (run before each stage commit) — the workspace pass (AVL default) **plus**
  an MRT pass over the packages you touched:
  ```
  RISC0_SKIP_BUILD=1 cargo clippy --workspace --exclude encrypted-spaces-ffi --all-targets --locked -- -D warnings
  RISC0_SKIP_BUILD=1 cargo clippy -p encrypted-spaces-changelog-core -p encrypted-spaces-sdk -p encrypted-spaces-ff-test --features mrt --all-targets --locked -- -D warnings
  ```
  From P4 on, add `-p encrypted-spaces-demo -p encrypted-spaces-demo-test-harness` to the MRT
  clippy line (once their passthrough exists).
- End each stage with `jj commit -m '<the stage subject below>'` — closes the stage
  commit, opens the next. Keep stages separate; don't squash. To publish/PR a phase,
  set its bookmark to the tip and push it — Phase A `trev/native-ops-mrt`, Phase B
  `trev/tree-fs-mrt` (e.g. `jj bookmark set trev/native-ops-mrt -r @-` then
  `jj git push --bookmark trev/native-ops-mrt --allow-new`).

---

## 1. Global adaptation rules (the measured `old → MRT` delta)

Apply these wherever you translate reference code. They are the entire reason this
is a port and not a cherry-pick.

1. **Writes changed type + became order-sensitive.**
   `OpVerifyResult.write_steps` is now `Vec<WriteOp>` (was `Vec<TraceStep>`). The
   MRT seam applies them **in vector order with no sort/dedup** (AVL is
   write-order sensitive). For multi-write ops — tree-fs create (parent record +
   child record), move/delete (subtree) — emit writes in the order they must apply.
2. **`MerkStorage::snapshot()` → `checkpoint()`** at every call site.
3. **Proof/witness API was replaced.** Gone: `PrunedMerkleTree`, `create_trace`,
   `encode_pruned_compact`, `decode_pruned_compact_to_merk`, `pruned_to_merk`,
   `apply_batch`, `collect_range`. Use the new trace API from
   `ffproof_tracer_shared`: `TraceInterface`, `TraceReader`, `TraceReplayer`,
   `WriteOp`, `ProvenRead`, `ReadOp`. **Reads are unchanged**:
   `OpReader::read(ReadOp) -> ProvenRead` is byte-identical, and `ReadOp`
   (`Key`/`Prefix`/`Range`) is unchanged.
4. **`ffproof/tracer` standalone crate was removed.** Trace/witness functionality
   now comes via the `merk` dependency (`trev/tracer_plus_bpt`) and
   `ffproof_tracer_shared`. Repoint imports; delete any copied tracer-crate files.
5. **Genesis was re-baselined.** `INITIAL_INTERNAL_DATA_COMMITMENT_HEX` changed.
   Never hardcode the old root. Any baseline reset or golden-root assertion must
   read MRT's current value (grep it on `origin/trev/mrt`).
6. **Stored keys must be prefix-free** (MRT/radix requirement: no stored key may be
   a prefix of another). Tree-fs keys already satisfy this — record tag `b"/info"`
   (`0x2F…`) never prefixes dir tag `b"SHA2"` (`0x53…`); the codec test asserts it.
   Do not introduce a stored key that prefixes another.

---

## Phase A — Native-ops framework on MRT · branch `trev/native-ops-mrt`
*Self-contained: framework + chat & table-fs verifiers, **no tree-fs, no UI change**.
Independently buildable, testable, and mergeable to `trev/mrt`. P2 (the long pole)
lives here, so the riskiest work is proven before tree-fs exists.*

## Stage P0 — Baseline & delta confirmation
**Goal:** prove the base builds and the adaptation rules still hold at your pinned
`trev/mrt` tip (it is force-pushed, so re-verify rather than trust this doc).

**Steps:** confirm symbols on your base: `OpReader`/`ReadOp` unchanged;
`OpVerifyResult.write_steps: Vec<WriteOp>`; `validate_user_access` present;
`TraceReplayer`/`WriteOp` exported from `ffproof_tracer_shared`; current
`INITIAL_INTERNAL_DATA_COMMITMENT_HEX`. Note any drift from §1 in the commit message.

**Gate (MRT, not AVL):**
```
RISC0_SKIP_BUILD=1 cargo check -p encrypted-spaces-changelog-core --features mrt
RISC0_SKIP_BUILD=1 cargo test  -p encrypted-spaces-changelog-core --features mrt --lib
```
Pass = both succeed, the test reports >0 tests, **and** you confirmed `--features mrt`
actually selects `merk::mrt` (genesis `0fca009d…`, not AVL `7ac1d1e9…`) — else you are
validating the wrong backend. **Commit** `P0 — baseline (base <mrt-SHA>)`.

## Stage P1 — Native-op framework + dispatch (ops stubbed)
**Goal:** the `NativeOp` verifier exists and is registered, but every op rejects.
**Source:** reference `Stage 1` (`45b32851`, enum + key helpers) **+ `Stage 2 — The
native op + dispatch` (`27d33095`)** — Stage 2 is where `native_ops.rs` and the
`OpVerifier` dispatch first appear; borrow its *shape* but stub/reject every handler
for P1 — **+ `B1`** (`030ce0e5`: `sdk/src/native_op.rs` submit plumbing + server
wiring, native still rejected).
**Apply:** rule §1.1 (write type), §1.2.
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo check -p encrypted-spaces-changelog-core -p encrypted-spaces-sdk --features mrt
RISC0_SKIP_BUILD=1 cargo test  -p encrypted-spaces-changelog-core --features mrt native_op
```
Pass = compiles; a "native op rejected / dispatch" test runs and passes (>0).
**Commit** `P1 — native-op framework + dispatch`.

## Stage P2 — Proof seam on the MRT trace model *(the long pole)*
**Goal:** exactly **one** native op proves and verifies end-to-end on MRT.
**Source:** reference `B2`/`B3` — as *guidance only*; the witness/guest code is
rewritten against the new API.
**Apply:** rules §1.3, §1.4, §1.5 (this stage is where they bite).

**Server-accept prerequisites (from reference `B2`) — the gate cannot pass without these:**
1. **Unblock + expose.** Remove the server's hard reject of `OpType::Native`
   (`backend/server/src/db.rs` ~1725), and make the verifier/codec usable: `native_ops`
   is currently `mod` (private) with `pub(crate)` handler consts, and there is no public
   SDK `submit_*_native`/codec — so today a native op cannot even be constructed. (M1 is
   a verifier *slice*, not a usable op; this is where it becomes usable.)
2. **Native-aware hash-backed values.** The server discovers referenced hashes by parsing
   a signed entry's KVs as *column keys* (`db.rs` ~1889), but native entries are
   marker/payload KVs — so a hash-backed value the verifier writes (`messages.content`,
   **and for the inode ops `name`/`mime_type`**) is seen as *unreferenced* and rejected
   (`db.rs` ~1813), or if omitted leaves a digest with no hash-store material. Port the
   reference's native-aware path so referenced hashes come from the op's *intended
   writes*, not the literal entry KVs. **The FS-only path does not dodge this** — inode
   `name`/`mime_type` are hash-backed too.
3. **Teach `parse_key` the native markers.** `parse_key` accepts only `action_marker`
   among marker sub-tags (`backend/storage-encoding/src/keys.rs` ~811); add
   `native_op`/`native_payload` so generic server/debug/storage parsing isn't blind to
   native entries. (Survivable for M1's private byte-compare; required once the server
   processes Native.)

**Deliverable:** port the reference's `test_native_update_message_in_ff_proof_batch`
(`ffproof/integration_tests/tests/integration_tests.rs`, pkg `encrypted-spaces-ff-test`)
onto the MRT trace model — a native op crossing a batch boundary, attested in a real
FF proof.
**Gate — must actually prove; do NOT set `RISC0_SKIP_BUILD`:**
```
RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-ff-test --features mrt --test integration_tests \
  test_native_update_message_in_ff_proof_batch -- --nocapture
```
Pass = the test **runs to completion** and passes. It is a **FAILURE** if output
contains `Skipping … RISC0_SKIP_BUILD is set` or reports 0 tests — this test
self-skips under `RISC0_SKIP_BUILD`, the exact trap that would let the proof seam go
green without proving anything. (The changelog-core unit tests from P1 do **not**
satisfy P2 — they don't run the guest.) **Commit** `P2 — native proof seam (MRT trace)`.

## Stage P3 — Per-op verifiers (chat + table-fs)
**Goal:** all 13 verifiers ported (send/update/delete message; add/delete reaction;
add_attachment; create_channel; update_channel_description; set_user_name;
add_inode; rename_inode; move_inode; delete_inode_recursive).
**Source:** port the **final state of each verifier at the reference tip**
(`trev/native-ops-tree-fs`) — *not* a replay of intermediate commits, which would
re-introduce behavior later fixed by hardening (`2c57e308` empty-write-set no-op +
rename_inode ACL fix; `ae924192` update_channel_description missing-target no-op).
Use the commit log only as the **inventory** of the 13 ops: `update_message`
(foundation) + rollout `Stage 2..12` (delete_reaction, send_message, add_reaction,
add_attachment, delete_message, update_channel_description, set_user_name,
rename_inode, move_inode, add_inode, delete_inode_recursive) + **`create_channel`**
(arrives via `4a913afe` / merge `22e02930`, not a clean "Stage 13"). Confirm you have
all 13 by grepping the tip's `native_ops.rs` dispatch.
**Apply:** §1.1 (write order). Reads port unchanged.
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-changelog-core --features mrt native_ops
```
Pass = the native↔data-driven differential tests run and pass (>0). Do ops
incrementally; commit per op or per small group. **Commit(s)** `P3 — <op> verifier`.

## Stage P4 — Self-consistency harnesses
**Goal:** fs + chat consistency suites pass in both `Wrapper` and `Native` modes.
**Source:** reference `a08a15ad`, `74e2684f`, `c0901cf7`, `59aa9db9`
(`test-harness/tests/{fs,chat}_consistency.rs`, `fs_test_model.rs`,
`chat_test_model.rs`).
**Apply:** §1.5 (update any golden roots to MRT genesis). **First add the `mrt`
passthrough** the harness gates need (one-time, this is the only new feature wiring
the port introduces): `encrypted-spaces-demo` →
`mrt = ["encrypted-spaces-sdk/mrt", "encrypted-spaces-changelog-core/mrt"]`, and
`encrypted-spaces-demo-test-harness` → `mrt = ["encrypted-spaces-demo/mrt"]`. (All other
crates already carry `mrt` on `trev/mrt`.)
**Gate:**
```
cargo test -p encrypted-spaces-demo-test-harness --features mrt --test fs_consistency
cargo test -p encrypted-spaces-demo-test-harness --features mrt --test chat_consistency
```
Pass = both binaries run; output includes the `*_native_writes` cases. **Commit**
`P4 — self-consistency harnesses`.

## Stage P4b — Native benchmark rows *(closes Phase A)*
**Goal:** the `fs_*_native` + chat-native cases emit cycle rows beside the existing
data-driven rows on MRT's benchmark — **no tree rows yet**.
**Source:** reference `e4074cb1` ("bench: add native ffchat cases") on
`ffchat_cycle_benchmarks.rs`. Rewrite the cycle/witness measurement against the new
trace model (§1.3); reconcile onto MRT's already-present `#209` benchmark.
**Apply:** §1.3, §1.5 (new genesis baseline).
**Gate (proves — `RISC0_DEV_MODE=1`, no `RISC0_SKIP_BUILD`):**
```
RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --features mrt --bench ffchat_cycle_benchmarks -- fs_file_insert_native
```
Pass = output includes the `fs_file_insert_native` row (and the other `*_native`
rows). **Commit** `P4b — native benchmark rows`.

**▶ Phase A complete** — `trev/native-ops-mrt` builds on MRT, all native ops prove,
harnesses + native bench green. Land/PR it on its own; Phase B stacks on top.

## Phase B — Tree-fs on MRT · branch `trev/tree-fs-mrt` (stacks on Phase A)
*Branch off Phase A's tip and confirm it's green before adding tree-fs. This phase
introduces the Tauri/frontend change (P6) — Phase A had none.*
```
jj new trev/native-ops-mrt            # Phase A's tip
jj bookmark create trev/tree-fs-mrt   # Phase B branch
# sanity: re-run P0's gate (and ideally P2's) so you start from a green base
```

## Stage P5 — Tree-fs codec + native ops
> **Superseded codec.** As shipped, P5 ported the reference *tip's* flat codec
> (`/_fs ‖ be32(label)* ‖ be32(0)`), not the tag scheme below — and it copied the
> AVL-era per-key move/delete onto MRT instead of using `MovePrefix`/`DeletePrefix`.
> The intended key model (the `/dir`+`/info` inode scheme + prefix-op lowering) is
> specified in [`DESIGN_TREE_FS_KEY_MODEL.md`](DESIGN_TREE_FS_KEY_MODEL.md); treat
> the source/tag note here as historical.

**Goal:** tree-fs create/read/rename/move/delete round-trip via native ops.
**Source:** reference `T0`/`T1` (`tree_fs.rs`, `files_tree/codec.rs`,
`tree_fs_*` verifiers in `native_ops.rs`, `submit_tree_fs_*` in SDK). Use the
current tag scheme (`TAG_DIR = b"SHA2"`, `TAG_INODE = b"/info"`).
**Apply:** §1.1 (create/move/delete write order); §1.6 (verify prefix-free, don't
re-engineer).
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_codec_
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_
```
Pass = `tree_fs_codec_*` (incl. namespace/depth + reject tests) and the `tree_fs_*`
roundtrips incl. `tree_fs_removed_user_write_rejected` all run and pass (>0).
**Commit** `P5 — tree-fs codec + native ops`.

## Stage P6 — Tree-fs model + harness + Tauri
**Goal:** `TreeFsModel`, the `FsBackend::Tree` consistency mode, and the Tauri
serialized-handle path (commands + frontend) all work.
**Source:** reference `T2`/`T3`/`T4` (`files_tree/mod.rs`, `commands.rs`,
`demos/tauri/lib`+`components`, `TreeFsModel`, `fs_consistency` tree arm).
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_model
cargo test -p encrypted-spaces-demo-test-harness --features mrt --test fs_consistency   # must include tree cases
npm --prefix demos/tauri run build
```
Pass = `tree_fs_model*` runs; `fs_consistency` output includes the tree backend
cases; the frontend builds. **Commit** `P6 — tree-fs model + harness + Tauri`.

## Stage P7 — Tree benchmark rows *(closes Phase B)*
**Goal:** the `fs_tree_*` cases emit cycle rows beside the native/data-driven FS rows
(the `fs_*_native` rows already landed in P4b).
**Source:** reference `T5` (`ffchat_cycle_benchmarks.rs`, the `fs_tree_*` cases only).
Rewrite the cycle/witness measurement against the new trace model; reconcile onto the
benchmark as it stands after P4b.
**Apply:** §1.3, §1.5 (new genesis baseline).
**Gate (proves — `RISC0_DEV_MODE=1`, no `RISC0_SKIP_BUILD`):**
```
RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --features mrt --bench ffchat_cycle_benchmarks -- fs_tree
```
Pass = output includes every `fs_tree_*` row. **Commit** `P7 — ffchat tree benchmarks`.

---

## Risk & sequencing notes
- **Phase A (P0–P4b) is the standalone deliverable** — framework + all non-tree
  verifiers + harnesses + native bench, mergeable to `trev/mrt` on its own and useful
  beyond tree-fs. **Phase B (P5–P7)** stacks tree-fs and is the only phase that touches
  the frontend.
- **P2 is the long pole** (proof-harness rewrite against the new trace model) and it
  lives in **Phase A** — so the riskiest work is proven before any tree-fs exists.
  Keep it minimal — one op — and stop.
- **P3 and P5 are low-risk** (read API stable, writes mechanical) — the bulk of the
  feature ports cheaply once P2 works.
- **P5 gets a free win** — tree-fs keys are already MRT-prefix-free.
- **P4b / P7 are medium** (witness measurement rewrite + genesis re-baseline).
- If `trev/mrt@origin` force-updates mid-port, finish the current stage, then
  `jj git fetch` and `jj rebase -b @ -d trev/mrt@origin` to move your stack onto the
  new tip; re-run the **P0** gate. Phase B likewise rebases on Phase A if A advances.
