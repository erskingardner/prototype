# PLAN — Tree-fs `/dir`+`/info` key model (execution)

Replace the shipped flat tree-fs codec with the `/dir`+`/info` inode model so
listing is one level and move/delete lower to MRT `MovePrefix`/`DeletePrefix`
(O(depth)). Implements the spec in
[`DESIGN_TREE_FS_KEY_MODEL.md`](docs/native_ops_plans/DESIGN_TREE_FS_KEY_MODEL.md);
this plan is the *how/when*.

## How to execute (agent)
Do the stages **in order** (K0 first — it gates the rest). For each stage:
1. Make the changes in **Touches**.
2. Add the named tests in **Tests to add** (these are deliverables, not optional).
3. Run the stage **Gate** *and* the **per-stage lint gate** (below). Both must be
   green.
4. **Commit** with the given message. Do **not** start the next stage until the
   current gate passes; if a `STOP-AND-REPORT` condition fires, halt and report.

Every gate command below is runnable and has an objective pass/fail. No stage
requires a human judgment call to proceed.

## 0. Context & decisions

- **Spec:** `DESIGN_TREE_FS_KEY_MODEL.md` (key model §2, value §3, ops + verifier
  preconditions §4).
- **Replaces** the flat codec shipped under `PLAN_PORT_MRT.md` §P5 on
  `trev/tree-fs-mrt`. **Greenfield** — no migration (prototype, no persisted data).
- **Decisions already taken (do not re-litigate mid-execution):**
  - **Name encryption — deferred.** Store the name as plaintext bytes.
  - **MIME — deferred.** Not stored; derived client-side from the name extension
    (`mime_from_extension`).
  - **`content_hash` — raw 32 bytes** in the value; hex↔raw at the SDK/codec edge.
  - **`FsHandle` → `Vec<[u8;32]>`**; the `FsHandleWire` command contract changes
    with it (K4) — not deferrable. Only the `files.tsx` component is deferred.
  - **Proven raw-read wire path** rides with `PLAN_TAURI_TREE_FS.md` — out of scope.
- **Key-ceiling finding.** `changelog::MAX_KEY_LEN = 64` is enforced only in
  `ChangelogEntry::new()` (`changelog.rs:191`) on *signed-entry* keys (for a native
  op: the short `native_marker_key()`/`native_payload_key()`). Verifier-emitted
  `/_fs` `WriteOp` keys never pass through it. So the only cap on record keys is the
  codec's `MAX_FS_KEY_LEN = 64` (`tree_fs.rs:23`, `files_tree/codec.rs:28`) — raise
  those, no global change.

## Goal
tree-fs create / list / rename / move / delete via native ops on the `/dir`+`/info`
codec, with **move → `MovePrefix`** and **delete → `DeletePrefix`**, proven
end-to-end on MRT; the `fs_consistency` tree backend and `fs_tree_*` benches green.

## Conventions

`--features mrt` on every build/test/lint.

**RISC0 env by gate type:**
- *Pure codec/model/consistency* gates don't touch the FF proof — run with **no
  RISC0 env** (or `RISC0_SKIP_BUILD=1` only to skip the unused guest *build*).
- *Proof* gates (assert a proof / cycles / a native roundtrip through the prover)
  use **`RISC0_DEV_MODE=1`**, **never `RISC0_SKIP_BUILD`** (proof tests self-skip
  under it), single-threaded (`--test-threads=1`).

**Per-stage lint gate (runs at every stage before Commit):**
```
cargo fmt --all -- --check
RISC0_SKIP_BUILD=1 cargo clippy --workspace --exclude encrypted-spaces-ffi --all-targets --locked -- -D warnings   # AVL
RISC0_SKIP_BUILD=1 cargo clippy -p <touched pkgs> --features mrt --all-targets --locked -- -D warnings          # MRT
```

Commit per stage; don't squash. Branch `trev/tree-fs-keymodel` off
`trev/tree-fs-mrt`.

---

## Stage K0 — prerequisites & spike  *(blocks K1+)*
**Goal:** the model's two load-bearing assumptions hold — the key ceiling admits
deep records, and a `MovePrefix`/`DeletePrefix` change **proves correctly** on MRT.
**Touches:**
- Raise `MAX_FS_KEY_LEN` 64 → **4096** (merk's `MAX_KEY_LEN`, `…/mrt/tree.rs`) in
  `tree_fs.rs:23` and `files_tree/codec.rs:28`; recompute `MAX_CHILD_DEPTH`. Add a
  comment recording why native `WriteOp` keys are exempt from
  `changelog::MAX_KEY_LEN` (§0). No `changelog` change.
**Tests to add** (in `changelog_core`, using the existing native-op proof harness
— see how a flat `tree_fs_*` proof test seeds a tree and calls the FF prove path):
- `move_prefix_proves` *(proof)* — seed a small tree; build a change whose
  `write_steps = vec![WriteOp::MovePrefix { from, to }]` by **hand** (do not depend
  on K2's verifier); prove it under `RISC0_DEV_MODE=1`; assert the proof **verifies**
  and the recomputed DC **equals** a reference tree that applied the same relocate
  directly. Add a sibling case for `DeletePrefix`.
  - **STOP-AND-REPORT** if the proof fails or the DC differs: the in-guest replayer
    does not support the prefix op under proof → the whole premise fails; halt the
    plan and report (do not proceed to K1).
- `max_depth_record_key_encodes` *(pure)* — `encode_record_key` of a
  `MAX_CHILD_DEPTH`-deep path returns `Ok` with length ≤ `MAX_FS_KEY_LEN`; one level
  deeper returns the length error.
**Gate:**
```
RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-changelog-core --features mrt move_prefix_proves -- --test-threads=1
cargo test -p encrypted-spaces-changelog-core --features mrt max_depth_record_key_encodes
```
Both pass. (Efficiency — that move is *O(depth)*, not O(subtree) — is **observed at
K5's bench**, not asserted here; K0 only proves correctness.) **Commit** `K0 — raise
codec key ceiling + prove MRT prefix ops`.

## Stage K1 — codec
**Goal:** the `/dir`+`/info` codec + `Inode` value — prefix-free, one-level listing.
**Source:** recovered inode codec `40f2ff6cf:ffproof/changelog_core/src/tree_fs.rs`
(`Inode`, `derive_inode_id`, key encoders), **refined** per DESIGN §2 — the record
lives under the *parent's* `/info`, the children container under `/dir` (the
original put the record at the end of the node's own path → no one-level listing).
Extract it with `git show 40f2ff6cf:ffproof/changelog_core/src/tree_fs.rs`.
**Touches:** `ffproof/changelog_core/src/tree_fs.rs` and the demo mirror
`demos/tauri/src-tauri/src/files_tree/codec.rs` (keep byte-identical):
- consts `FS_KEY_NAMESPACE=b"/_fs"`, `TAG_DIR=b"/dir"`, `TAG_INFO=b"/info"`,
  `INODE_ID_LEN=32`, `MAX_FS_KEY_LEN` (K0), derived `MAX_CHILD_DEPTH`.
- `Inode` (DESIGN §3 72-byte header; **plaintext name**; raw-32 `content_hash`).
- `derive_inode_id(parent_clc) = SHA(parent_clc ‖ b"id")`.
- `encode_record_key(path)` = `CONTAINER(parent) ‖ /info ‖ h`;
  `encode_container_prefix(path)`; `encode_children_listing_prefix(dir)` =
  `CONTAINER(dir) ‖ /info`; `decode_record_key`; `validate_inode_id`.
**Tests to add** (`changelog_core`, pure):
- `tree_fs_codec_roundtrip` — encode→decode for a file record, a dir record, and a
  root child; values round-trip exactly.
- `tree_fs_codec_rejects` — bad version/flags, oversized name, nonzero padding,
  trailing bytes, zero inode id, over-length key each return the right `CodecError`.
- `tree_fs_listing_prefix_excludes_grandchildren` — for parent `D`, child `C`,
  grandchild `G`: assert `encode_record_key([D,C])` **starts with**
  `encode_children_listing_prefix([D])`, and `encode_record_key([D,C,G])` does
  **not**. (This is the one-level-listing invariant.)
**Apply:** §1.6 (verify prefix-free; don't re-engineer); DESIGN §2.
**Gate** (pure codec — no RISC0 env):
```
cargo test -p encrypted-spaces-changelog-core --features mrt tree_fs_codec
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_codec_   # demo mirror
```
all three new tests + existing codec tests pass. **Commit** `K1 — /dir+/info codec`.

## Stage K2 — verifiers
**Goal:** the four `tree_fs_*` verifiers on the new codec, move/delete lowered to
prefix ops, all preconditions enforced.
**Touches:** `ffproof/changelog_core/src/native_ops.rs`
(`tree_fs_create`/`rename`/`move`/`delete`):
- **create** — validate parent first: root (`[]`) is an *implicit* directory; a
  non-root parent must have an existing `kind == Directory` record (reject "parent
  does not exist" / "not a directory"). Then derive `h` from `entry.parent_clc`,
  require the target key vacant, emit one `Put`. No parent-counter. *(Stops orphan
  records under a forged id-chain.)*
- **rename** — missing target → no-op (empty `write_steps`); else `Put` (new name +
  `mtime`).
- **move** — missing source → no-op; same-parent (`CONTAINER(A)==CONTAINER(B)`) →
  no-op / `mtime`-only `Put` (short-circuit **before** the conflict check). Else
  `MovePrefix { from: CONTAINER(A) ‖ /dir ‖ h_N, to: CONTAINER(B) ‖ /dir ‖ h_N }`
  (dir only) + `Delete`/`Put` of the record. Preconditions (DESIGN §4): source ≠
  root; no-cycle; dest parent — root implicit dir, else existing `Directory`; no
  dest conflict (cross-parent). Drop `next_child_label` checks.
- **delete** — missing source → no-op; else `DeletePrefix { CONTAINER(A) ‖ /dir ‖
  h_N }` (dir only) + `Delete` of the record. Source ≠ root.
- reads via `OpReader`; `(TREE_FS_*_KIND, _VERSION)` dispatch arms unchanged.
**`write_steps` capture point (for the shape assertions):** call the verifier fn
directly — `tree_fs_move(&entry, &payload, &mut reader)` — and inspect the returned
`OpVerifyResult.write_steps`. Seed the tree with a `TestOpReader` exactly as the
existing flat `tree_fs_*` verifier unit tests do (same module); no proving needed
for the shape tests.
**Tests to add** (`changelog_core`):
- `tree_fs_move_cross_parent_emits_one_moveprefix` *(pure, shape)* — 3-level tree,
  move a level-2 dir under root; assert `write_steps` contains **exactly one**
  `WriteOp::MovePrefix` plus the record `Delete`+`Put`, and **zero** per-subtree
  `Put`/`Delete`.
- `tree_fs_delete_dir_emits_one_deleteprefix` *(pure, shape)* — assert exactly one
  `WriteOp::DeletePrefix` + the record `Delete`.
- `tree_fs_create_rejects_absent_parent`, `tree_fs_create_rejects_file_parent`
  *(pure)* — both error.
- `tree_fs_{rename,move,delete}_missing_target_noop` *(pure)* — `write_steps` empty.
- `tree_fs_move_same_parent_noop` *(pure)* — `write_steps` empty (or mtime-only).
- `tree_fs_native_roundtrip` *(proof)* — create→rename→move→delete proven
  end-to-end; final read surface matches a model.
**Apply:** §1.1 (delete-before-put at the same key); DESIGN §4.
**Gate:**
```
cargo test -p encrypted-spaces-changelog-core --features mrt tree_fs_   # pure shape/precondition tests
RISC0_DEV_MODE=1 cargo test -p encrypted-spaces-changelog-core --features mrt tree_fs_native_roundtrip -- --test-threads=1
```
shape tests assert the prefix-op counts above; roundtrip proves. **Commit** `K2 —
verifiers on MovePrefix/DeletePrefix`.

## Stage K3 — SDK
**Goal:** the submitters + the `Vec<[u8;32]>` handle, with create returning the
accepted id.
**Touches:** `sdk/src/native_op.rs` —
`submit_tree_fs_create/rename/move/delete`; **create returns the accepted id**
(`derive_inode_id` of the committed `parent_clc`, §0 id contract); `FsHandle =
Vec<[u8;32]>` with `into_wire`/`from_wire`; rework
`tree_fs_created_handle_from_writes` to parse the new `…/info/h` key; raw-read
helpers build `encode_container_prefix` / record keys.
**Tests to add** (`sdk`, non-proof — `LocalTransport`):
- `submit_tree_fs_create_returns_accepted_id` — after a create, the returned
  handle's last id `== derive_inode_id(committed parent_clc)`.
- `fs_handle_wire_roundtrip` — `from_wire(into_wire(h)) == h` for root and a
  multi-level handle; malformed wire (odd hex, wrong length) errors.
**Gate** (non-proof):
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-sdk --features mrt tree_fs
```
**Commit** `K3 — SDK submitters + id-chain handle`.

## Stage K4 — demo API + wire contract + model
**Goal:** the demo tree API on id-chain handles, the `FsHandleWire` contract, and
the consistency model/MIME updated.
**Touches:**
- `demos/tauri/src-tauri/src/files_tree/mod.rs` — `list_children_tree` scans
  `CONTAINER(D) ‖ /info` (one level, no client-side depth filter); `read_node_record`,
  `download_file_tree`, create/rename/move/delete; `FsHandle = Vec<[u8;32]>`;
  **empty-root returns `[]`** (review #6).
- **Handle wire contract (breaking — not deferred):** `FsHandleWire = string[]`
  (each id 64-char hex), `FsHandle::from_wire`/`into_wire` in `files_tree/mod.rs`;
  thread through the 7 tree commands in `commands.rs`; update `lib/types.ts`
  (`FsHandleWire`, `ROOT_HANDLE`, `handleKey`) + `lib/api.ts`. `files.tsx` untouched.
- **MIME:** update `fs_test_model.rs` so the tree model's *expected* MIME comes from
  `mime_from_extension(name)` (not the requested MIME) — or drop the MIME-equality
  assertion for the tree backend — else consistency fails on non-matching uploads.
- `fs_test_model.rs` `TreeFsModel` + the `fs_consistency` tree backend — adapt to
  id-chain handles + the MIME change.
**Tests to add / update** (non-proof):
- `tree_fs_list_empty_root_returns_empty` — fresh space, `list_children_tree([])`
  returns `[]` (no error).
- update the existing `fs_consistency` `*_tree` cases to id-chain handles; they must
  stay green.
**Gate** (non-proof):
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo-test-harness --features mrt fs_consistency -- --test-threads=1
npm --prefix demos/tauri run build
```
tree backend green (incl. empty-root `[]`); `npm build` type-checks the new
`FsHandleWire`. **Commit** `K4 — demo API + id-chain handles (breaking FsHandleWire
contract)`.

## Stage K5 — bench
**Goal:** `fs_tree_*` rows on the new codec; move/delete cycles drop (the O(depth)
payoff, observed).
**Touches:** `ffproof/integration_tests/benches/ffchat_cycle_benchmarks.rs` —
`TreeFsFixture` + `run_fs_tree_*` build through the new submitters (32-byte-id
handles); `create_tree_fs_node` returns the accepted id.
**Gate:**
```
RISC0_DEV_MODE=1 cargo bench -p encrypted-spaces-ff-test --features mrt --bench ffchat_cycle_benchmarks -- fs_tree
```
Objective pass: **every `fs_tree_*` row prints**, and the measured
`fs_tree_directory_move` and `fs_tree_directory_delete` cycles/op are **strictly
below** the shipped flat-scheme baseline of **6,000,000** and **3,700,000**
respectively (they should land far lower — that's the prefix-op payoff).
- **STOP-AND-REPORT** if either is **not** below its baseline: the verifier did not
  actually lower to the prefix op (it's still materializing the subtree). Record the
  numbers and halt. **Commit** `K5 — ffchat tree benches on the new codec`.

---

## Risks / open questions
- **Plaintext names** (deferred encryption): names visible in tree records —
  acceptable for the prototype; a later stage restores encryption.
- **`MovePrefix` witness** is the load-bearing assumption; **K0 must pass before
  K1** (its `STOP-AND-REPORT` halts the plan if the prefix op can't prove).
- **`FsHandle` `Vec<[u8;32]>`** is pervasive (SDK, demo, model, bench) and the
  `FsHandleWire` contract changes with it (K4). Only `files.tsx` defers.
- **`next_child_label` removal** — confirm no consumer (model, tests, bench fixture)
  depends on the old per-parent counter.

## Out of scope
- Name encryption; MIME storage (deferred §0).
- The `files.tsx` component tree wiring + the proven raw-read wire path
  (`PLAN_TAURI_TREE_FS.md`). *(The `FsHandleWire` wire type is in K4.)*
- Migrating flat-scheme records (greenfield).
