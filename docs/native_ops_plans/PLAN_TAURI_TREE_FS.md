# PLAN — Tauri integration for the tree-fs backend

Make the `/dir`+`/info` tree-filesystem backend usable from the **shipping Tauri
app** (over `WebSocketTransport`), not just the in-process `LocalTransport` test
harness. Builds on the key-model branch (`trev/tree-fs-keymodel`).

## How to execute (agent)
Do the stages **in order** (T-A first — it gates the rest). For each stage:
1. Make the changes in **Touches**.
2. Add the named tests in **Tests to add** (deliverables, not optional).
3. Run the stage **Gate** *and* the **per-stage lint gate** (Conventions). Both
   must be green.
4. **Commit** with the given message. Don't start the next stage on a red gate;
   if a `STOP-AND-REPORT` fires, halt and report.

Every gate is a runnable command with an objective pass/fail.

## 0. Context & current state

**Already done by the key-model work (`trev/tree-fs-keymodel`):**
- Codec is the `/dir`+`/info` inode model; a directory listing is a **one-level**
  prefix scan (`CONTAINER(D) ‖ /info`), so a listing proof is **O(#children)**,
  not O(subtree). (This removed the old read-amplification risk.)
- `FsHandleWire = string[]` (hex of 32-byte ids) in `lib/types.ts` / `lib/api.ts`;
  the 7 `*_tree` Tauri commands are registered; `files_tree::list_children_tree`
  already returns `[]` for an empty root.
- Tree reads work **only under `LocalTransport`** (trusted, in-process).

**The two gaps this plan closes:**
1. **Production proven read path *(the blocker)*.** `WebSocketTransport::raw_read`
   is the unsupported trait default (`sdk/src/transport.rs:71`), and
   `database.proto` has no raw-read op. So every tree read helper
   (`list_children_tree`, `download_file_tree`, `read_node_record` in
   `files_tree/mod.rs`) fails over WebSocket.
2. **UI.** `demos/tauri/components/files.tsx` still calls the table APIs
   (0 tree calls today); the `string[]`-handle tree bindings in `lib/api.ts` are
   unused.

## Goal
The Tauri file browser performs tree-fs create / list / upload / download /
rename / move / delete against a real server over `WebSocketTransport`, with
**proven** reads verified against the client's data commitment (DC).

## Key design decision — reads must be proven (and *complete*)
`LocalTransport::raw_read` trusts the in-process server. A WebSocket client does
**not** trust the server, so the production raw read must return a **Merk proof**
the client verifies against its DC — mirroring `select`
(`prove_prefix`/`prove_keys` server-side, `proofs::verify_proof` client-side).
Two properties:
- **Key read:** inclusion — the returned value is what's at `key` under the DC.
- **Prefix read:** **completeness** — the returned entries are *all and only* the
  keys under `prefix` under the DC. A malicious server must **not** be able to
  omit a child from a listing. This is the load-bearing property; the range
  proof's boundary nodes are what enforce it (same as how `select` proves a query
  result is complete).

---

## Stage T-A — Proven raw-read over the wire  *(the blocker)*
**Goal:** a WebSocket client can do a `key` or `prefix` raw read and verify the
result against its DC, including **rejecting an incomplete prefix result**.
**Touches:**
- `backend/src/proto/database.proto`:
  - `message RawReadRequest { oneof target { bytes key = 1; bytes prefix = 2; }
    bytes commitment = 3; }`
  - `message RawReadResponse { repeated Entry entries = 1; bytes proof = 2; }`
    (reuse the existing `Entry`/kv message used by `SelectResponse`, or add one).
  - Wire into the oneofs at the **free** field numbers: `RawReadRequest raw_read =
    7;` in `DbRequest.operation`, `RawReadResponse raw_read = 9;` in
    `DbResponse.result`.
- Server dispatch (`backend/server/src/websocket.rs` — the `db_request::Operation`
  match; and `backend/server/src/db.rs`): add a `RawRead` arm beside `Select`.
  Handle at the current DC — `self.db.prove_keys(&[key])` / `prove_prefix(&prefix)`
  (`proofs.rs:179,202`) → return the matching `(key,value)` entries + proof bytes.
- `sdk/src/websocket_transport.rs`: implement `raw_read` (replace the unsupported
  default). Send the `RawReadRequest` via `send_request(DbRequest) -> DbResponse`,
  then **verify** the proof against `commitment` and return only verified entries;
  reject a commitment mismatch as `FastForwardRequired`. For a **key** read use
  `proofs::verify_proof(proof, &commitment, &[key])` (`proofs.rs:585`); for a
  **prefix** read use the *complete-range* verification (the same primitive
  `select` uses to prove a query result — confirm it rejects an omitted entry; if
  no such primitive exists for a raw prefix, that is the **STOP-AND-REPORT** below).
**Apply:** mirror `WebSocketTransport::select` (request/response framing +
proof-verify shape) and `LocalTransport::raw_read`'s commitment-check contract.
**Tests to add** (`sdk`, over a WebSocket transport pair — see the existing
`select`/`change` WS integration tests for the harness):
- `raw_read_key_over_ws` — seed a `/_fs` record; `raw_read_key` returns the
  verified `(key, value)`; a **tampered proof** and a **stale commitment** are
  each rejected (`Err`).
- `raw_read_prefix_over_ws` — seed several `/_fs` records under a parent's
  `CONTAINER ‖ /info`; `raw_read_prefix` returns **all and only** them; a
  **tampered proof** and a **stale commitment** are rejected.
- `raw_read_prefix_rejects_omitted_entry` *(the load-bearing one)* — drive the
  server (or hand-craft a response) to **omit one entry** from an otherwise-valid
  prefix result; the client **must reject** it. **STOP-AND-REPORT** if the
  verification cannot catch an omission — the prefix read isn't actually proven,
  and the design needs the complete-range primitive before proceeding.
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-sdk --features mrt raw_read
```
All three pass (incl. the omitted-entry rejection). **Commit** `T-A — proven
raw-read over the wire`.

## Stage T-B — Tree file browser UI
**Goal:** the file browser drives the tree backend end-to-end in the app.
**Touches:**
- `demos/tauri/components/files.tsx`: switch from the table APIs to the tree
  ones — navigate by `FsHandleWire` (`string[]`, root `[]`) and call
  `listInodesTree` / `uploadInodesTree` / `createFolderInodeTree` /
  `deleteInodeTree` / `renameInodeTree` / `moveInodeTree` / `downloadFileTree`
  (drag-drop move via `moveInodeTree`). The bindings already exist in `lib/api.ts`;
  `ROOT_HANDLE` / `handleKey` are in `lib/types.ts`.
- (The empty-root `[]` listing and the `string[]` wire format are already done —
  do **not** re-implement them.)
**Tests to add / update:**
- A `tree_fs_` demo/harness case that lists a fresh space's root and gets `[]`
  (likely already present — confirm it still passes).
- No new Rust; the UI change is type-checked by `npm build`.
**Gate:**
```
npm --prefix demos/tauri run build
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo --features mrt tree_fs_
```
`npm build` type-checks the tree-driven component; the demo tree tests stay green.
**Commit** `T-B — tree file browser UI`.

## Stage T-C — End-to-end over WebSocket + table/tree toggle
**Goal:** the tree path works app↔server over `WebSocketTransport`, and the
backend choice is deliberate.
**Touches:**
- An integration test (test-harness) exercising **create → list → upload →
  download → move → delete** through `WebSocketTransport` (not `LocalTransport`)
  end-to-end against a spun-up server.
- A runtime/feature **toggle** keeping the table backend available (tree-fs is a
  prototype baseline; don't delete the working table UI). A setting or
  `cfg`/env flag the UI reads to pick `*Tree` vs table commands.
**Tests to add:**
- `tree_fs_e2e_over_ws` — the full lifecycle above over a WebSocket pair; asserts
  the final read surface matches a model (reuse `TreeFsModel`).
**Gate:**
```
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-demo-test-harness --features mrt tree_fs_e2e_over_ws -- --test-threads=1
npm --prefix demos/tauri run build
```
Plus a manual smoke (`npm run dev` + a running backend). **Commit** `T-C —
tree-fs Tauri e2e + backend toggle`.

---

## Conventions
`--features mrt` on every build/test/lint (not a default; without it the gate
validates the wrong backend). **Per-stage lint gate (before each Commit):**
```
cargo fmt --all -- --check
RISC0_SKIP_BUILD=1 cargo clippy --workspace --exclude encrypted-spaces-ffi --all-targets --locked -- -D warnings   # AVL
RISC0_SKIP_BUILD=1 cargo clippy -p <touched pkgs> --features mrt --all-targets --locked -- -D warnings          # MRT
```
The raw-read path is a pure verify+apply read (no FF proof), so its gates use
`RISC0_SKIP_BUILD=1`, not `RISC0_DEV_MODE`. Commit per stage; don't squash.
Branch `trev/tree-fs-tauri` off `trev/tree-fs-keymodel`.

## Risks / open questions
- **Prefix completeness primitive (the real risk).** T-A hinges on the client
  being able to verify a prefix result is *complete*. `proofs::verify_proof` takes
  explicit keys (inclusion); confirm there is a range/query-proof verification
  that proves *no key in `[prefix, prefix_end)` was omitted* (this is what
  `select` already relies on). If only per-key inclusion exists, T-A's
  `raw_read_prefix_rejects_omitted_entry` test will fail — that's the
  STOP-AND-REPORT, and the fix is to expose/borrow the select query-proof verifier
  for the raw prefix range.
- **`download_file_tree`** is a single-key raw read of one `Inode` record, then a
  blob fetch by `content_hash` through the existing file-store path — cheap, no
  new wire op beyond the key read.
- **Empty/edge roots.** Confirm `prove_prefix` over an empty `CONTAINER([]) ‖
  /info` returns a verifiable "absent"/empty proof so a fresh space lists `[]`.

## Out of scope
- The Patricia/Merklized tree-fs backend (the `/dir`+`/info` model is the baseline).
- Migrating table-fs (`inodes`) data into tree-fs.
- Independent open items: the `removed_user_*` SDK deadlock (`#[ignore]`),
  `hash_store` / file-store GC — none required for Tauri tree integration.
