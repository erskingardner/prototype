# DESIGN — Tree-fs key model (`/dir` + `/info` on MRT)

The storage key/value model for the tree filesystem, and the verifier lowering
that makes its operations efficient on a **Merkle Radix Tree (MRT)**. This is a
design spec with an implementation outline; it is the intended target, not what
currently ships.

## Status & relationship to other docs
- **Supersedes** the flat codec described in `PLAN_PORT_MRT.md` §P5 and shipped on
  `trev/tree-fs-mrt` (`/_fs ‖ be32(label)* ‖ be32(0)`).
- **Resolves** the read-amplification open question in `PLAN_TAURI_TREE_FS.md`
  (the answer is this `/dir`+`/info` model, not a bolt-on child index).
- **Recovers & refines** the abandoned inode-keyed codec (`40f2ff6cf`,
  `tree_fs.rs`): same 32-byte deterministic inode ids and `Inode` value, but the
  record is placed under the *parent's* `/info` namespace so listing is one level.

## 1. Problem

The shipped tree-fs hits **none** of the three efficiencies MRT offers, because a
flat key scheme was paired with AVL-era verifiers copied verbatim onto MRT:

| lever | needs | shipped |
|---|---|---|
| one-level **listing** | a per-directory child *prefix* | ❌ scans the whole subtree, filters by key length |
| O(depth) **move** | `WriteOp::MovePrefix` | ❌ per-key `Delete`+`Put` over the subtree |
| O(depth) **delete** | `WriteOp::DeletePrefix` | ❌ per-key `Delete` over the subtree |

MRT's `WriteOp` vocabulary is `{ Put, Delete, DeleteRange, DeletePrefix,
MovePrefix }`. `MovePrefix { from, to }` is the **MRT subtree-relocate
primitive** (O(depth) re-point + re-hash of the spine; the moved subtree's nodes
and sub-hashes are untouched). AVL supports neither prefix op — which is *why* the
reference verifiers materialize subtrees by hand. The MRT port must lower
move/delete to these primitives, and adopt a key model whose listing is a prefix.

## 2. Key model

Two path tags alternate down the tree; nodes are addressed by a stable 32-byte
inode id, and a node's **record lives in its parent's `/info` namespace** while a
directory's **children live in its `/dir` namespace**.

```
FS_KEY_NAMESPACE = b"/_fs"
TAG_DIR          = b"/dir"     // descend into a directory's children container
TAG_INFO         = b"/info"    // a node's record, listed by its parent
INODE_ID_LEN     = 32
```

**Inode id** — deterministic and **verifier-derived** from the *accepted* signed
entry's parent changelog commitment at create time (no counter, no
read-modify-write):

```
derive_inode_id(parent_clc) = SHA(parent_clc ‖ b"id")   // 32 bytes, nonzero
```

**Id contract (not "unforgeable by secrecy").** `parent_clc` is public, so the id
is *predictable* — its integrity comes from **derivation + strict freshness**, not
from being unguessable:
- The **payload cannot choose the id.** The verifier ignores any
  caller-supplied id and recomputes it from the accepted `entry.parent_clc`.
- Under strict freshness, a create anchors at exactly one parent commitment, so
  the id is unique (collision = a SHA collision). A **stale / re-anchored** create
  derives a *different* final id (different `parent_clc`), so retries are not
  idempotent on the id.
- Therefore the **SDK must return the accepted id** from the committed entry —
  the caller cannot precompute and rely on it before acceptance
  (`sdk/src/native_op.rs` create path).

**Container prefix** of a directory `D` reached by the dir-hash chain
`[h₁ … h_m]` (root → D):

```
CONTAINER(D) = /_fs ‖ (TAG_DIR ‖ h_i)        for i = 1..m      // CONTAINER(root) = /_fs
```

**Two key kinds** under a directory `D`:

```
record key      :  CONTAINER(D) ‖ TAG_INFO ‖ h_child      → an Inode value (§3)
child container :  CONTAINER(D) ‖ TAG_DIR  ‖ h_child ‖ …   → that child's own subtree
```

So a directory appears twice: its **record** at `CONTAINER(parent) ‖ /info ‖ h_D`
and its **children container** at `CONTAINER(parent) ‖ /dir ‖ h_D ‖ …`. A file has
only a record (no container). The example `/dir/<h>/dir/<h>/info/<h>` is exactly
"descend two directories, then a child record."

**Why listing is one level.** `List(D)` = prefix-scan `CONTAINER(D) ‖ TAG_INFO`:

```
CONTAINER(D) ‖ /info ‖ h_c₁
CONTAINER(D) ‖ /info ‖ h_c₂           ← exactly D's direct children, full records inline
…
```

A grandchild is at `CONTAINER(D) ‖ /dir ‖ h_cᵢ ‖ /info ‖ h_g` — under the `/dir`
branch, *not* under `CONTAINER(D) ‖ /info`. `/dir` (`…2f 64…`) and `/info`
(`…2f 69…`) diverge at the byte after `/`, so the `/info` scan is a clean
contiguous range. **The record *is* the listing entry** — no separate index, no
denormalized copy to keep in sync.

**Prefix-free.** All record keys end `… ‖ /info ‖ h` (fixed 32-byte tail) and are
leaves (nothing is stored under a record); two records of equal length with
distinct 32-byte ids are never prefixes of one another; `/dir` vs `/info`
disambiguates record from container at every level.

**Depth budget — and a hard prerequisite.** A record at depth `d` (d dir
ancestors + leaf) is `4 (/_fs) + d·36 (/dir‖id) + 37 (/info‖id) = 41 + 36·d`
bytes. The MRT *substrate* allows `MAX_KEY_LEN = 4096`
(`merk …/mrt/tree.rs`) → `d ≤ (4096 − 41) / 36 ≈ 112`. **But the active codec
ceiling today is 64 bytes** — `MAX_FS_KEY_LEN = 64` (`tree_fs.rs:23`,
`files_tree/codec.rs:28`). At 64 B even a *single* grandchild record (77 B) is
rejected, so this model **cannot be implemented without first raising those two
codec caps** (stage K0), up to the MRT substrate max (4096; pick that for full
depth, or ≥ 545 for the flat scheme's old depth-14 parity).

**The global `changelog::MAX_KEY_LEN = 64` does *not* need to change.** It is
enforced only in `ChangelogEntry::new()` (`changelog.rs:191`) on the *signed-entry*
keys — for a native op those are the short `native_marker_key()` /
`native_payload_key()`. Verifier-emitted `/_fs` `WriteOp` keys never pass through
it and hit no length check on apply, so they are bound only by the codec cap above
and the merk substrate limit. (See `PLAN_TREE_FS_KEYMODEL.md` §0.)

Compact tags `//`/`/i` (`34 B`/level) shift `d` by only ~7 at 4 KB — not worth
the lost readability.

## 3. Inode value

Canonical: a 72-byte fixed header + the encrypted name, zero-padded to a 4-byte
multiple. **Identity is in the key, not here** — no inode id, no parent pointer,
so a move only relocates keys; values are untouched (beyond an optional `mtime`
bump).

| offset | size | field | rule |
|---|---|---|---|
| 0  | 4  | `version` u32 | == 3 |
| 4  | 4  | `flags` u32 | bit 0 = `FILE`; unset = `Directory`; other bits rejected |
| 8  | 4  | `author_uid` u32 | |
| 12 | 8  | `size` u64 | directories must be 0 |
| 20 | 8  | `ctime` i64 | |
| 28 | 8  | `mtime` i64 | |
| 36 | 32 | `content_hash` | file-store blob hash; directories must be all-zero |
| 68 | 4  | `name_len` u32 | ≤ 256 |
| 72 | `name_len` | `name_ciphertext` | encrypted filename; padding bytes must be 0 |

(Leaner than the shipped `NodeRecord`: no `node_id`, no `next_child_label`, no
magic/total_len. Decode rejects bad version/flags, oversized names, nonzero
padding, trailing bytes, and directory size/hash violations.)

**`content_hash` is raw 32 bytes** in the canonical value. The file API
(`sdk/src/file.rs`, `files_tree/mod.rs`) deals in **64-char hex** today, so the
conversion boundary is the SDK/codec edge: hex → raw on encode, raw → hex on
decode. The stored value is always raw 32 bytes; hex never appears on the wire or
in the tree.

**MIME — resolved, not stored.** The recovered `Inode` (v3) has no `mime_type`,
but the delivered tree-fs API/UI exposes one (`files_tree/mod.rs`). Decision:
**derive MIME client-side from the decrypted filename extension**
(`mime_from_extension`) at the API boundary, rather than storing it — the client
already holds the plaintext name, and this keeps the canonical value lean and
matches v3. *Alternative if explicit per-file MIME is required:* add a
length-prefixed `mime` variable field after the name (encrypted alongside it) and
bump `INODE_VERSION`. Pick one in K0; don't silently drop a field the UI reads.

## 4. Operations and their `WriteOp` lowering

Let `D` be the parent directory, `h = derive_inode_id(parent_clc)` the new id.

- **create(D, kind, name, …)** → *validate D* (root `[]` = implicit directory;
  non-root D must be an existing `Directory` record), then
  `Put { CONTAINER(D) ‖ /info ‖ h, Inode{…} }`. No parent-record update (id is
  CLC-derived, not counter-allocated). **If the new node is a directory, also
  `Put` its container sentinel** (see *MRT-primitive mechanics* below).
- **list(D)** → read-scan prefix `CONTAINER(D) ‖ /info`; decode each value as an
  `Inode`. One bounded, one-level scan; over the wire one contiguous proof of
  size O(#children).
- **rename(N, name)** → `Put` N's record with new `name_ciphertext` (+ `mtime`).
- **move(N: A → B)** (let `h_N` = N's id):
  - `MovePrefix { from: CONTAINER(A) ‖ /dir ‖ h_N, to: CONTAINER(B) ‖ /dir ‖ h_N }`
    — relocates N's whole subtree container (no-op / omitted for a file).
  - `Delete { CONTAINER(A) ‖ /info ‖ h_N }` + `Put { CONTAINER(B) ‖ /info ‖ h_N, … }`
    — relocate N's record (with `mtime` bump). (A single key, so explicit
    delete+put rather than a prefix op.)
  - Total: O(depth). N's id and all descendant ids/values are unchanged.
- **delete(N)**:
  - `DeletePrefix { CONTAINER(A) ‖ /dir ‖ h_N }` — the subtree (omitted for a file).
  - `Delete { CONTAINER(A) ‖ /info ‖ h_N }` — the record.
  - Total: O(depth).

### MRT-primitive mechanics (load-bearing — do not remove)

Two non-obvious requirements of the merk `MovePrefix`/`DeletePrefix` primitives.
Both are enforced in the verifiers; a future "simplification" that drops either
is a correctness/security bug.

- **Empty-directory container sentinel.** `MovePrefix { from, to }` **errors on an
  absent `from` prefix** (unlike the tolerant `DeletePrefix`). A freshly-created
  directory has nothing under its container until it gains a child, so moving an
  empty directory would fail. Fix: `create` seeds a one-key **sentinel** at
  `CONTAINER(dir) ‖ /cnt` (a fixed tag **byte-distinct from `/info` and `/dir`**,
  so it never appears in a `/info` listing nor masquerades as a sub-container).
  Every directory's container is therefore non-empty, so `move`/`delete` need no
  O(subtree) emptiness read — the source prefix is always present, keeping the op
  O(depth). The sentinel rides the `MovePrefix` and is removed by the
  `DeletePrefix`.
- **`MovePrefix` overwrites — so the destination must be proven vacant.** merk's
  `MovePrefix` uses **overwrite semantics** at the destination: if
  `CONTAINER(B) ‖ /dir ‖ h_N` (or the destination record key) is already occupied,
  the moved subtree **silently clobbers** it. So a cross-parent `move` must prove
  **both** the destination record key **and** (for a directory) the destination
  container are absent before emitting the `MovePrefix`. These are proven-absent
  reads — O(depth), not O(subtree), precisely because they're required empty.

All four verifiers derive/validate `h` and the affected keys from the
authenticated payload + parent CLC, then emit exactly the `WriteOp`s above.
`§1.1` write-order still applies where a delete precedes a put at the same key.

**Verifier preconditions (carry forward from the flat verifiers).** The flat
`tree_fs_*` enforce these; the new codec + prefix-op lowering must keep them,
since neither the codec nor `MovePrefix` self-checks structure.

*Missing target → no-op (all of rename/move/delete).* If the target record is
absent, return an empty `OpVerifyResult` (no `WriteOp`s) — matching the flat
verifiers (`native_ops.rs` rename/move/delete). Not an error.

*create(N under D)*
- **Parent must be a directory.** Root (`D == []`) is an **implicit** directory
  (no record); a non-root `D` must have an existing record with `kind ==
  Directory` — read it and reject "parent does not exist" / "not a directory".
  Without this, a forged id-chain `CONTAINER(D)` would let a create plant orphan
  records under a non-existent parent.
- **No conflict** — the new record key must be vacant (cryptographically assured
  by the CLC-derived `h`, but still checked).

*move(N: A → B)*
- **Source is not root** — `h_N` path non-empty (can't move `/`).
- **No cycle** — B's container is not inside N's subtree:
  `CONTAINER(B)` must not have `CONTAINER(A) ‖ /dir ‖ h_N` as a prefix.
- **Destination parent is a directory** — root (`B == []`) is an implicit
  directory; a non-root `B` must have an existing `Directory` record (reject if
  absent or `kind != Directory`).
- **Same-parent move is a no-op.** If `CONTAINER(A) == CONTAINER(B)` the source
  and destination record keys are identical (ids are stable), so there is nothing
  to relocate: emit no `WriteOp`s (or an `mtime`-only `Put` if a touch is wanted)
  and short-circuit *before* the conflict check. This case must be handled first,
  or the conflict check below would reject the node against itself.
- **No destination conflict** (cross-parent only) — for `A ≠ B`, the target record
  key `CONTAINER(B) ‖ /info ‖ h_N` (and container, for a dir) must be vacant; a
  proven-absent read of the destination range, or reject if occupied.
- **Missing source → no-op** (global rule above).
- The flat scheme's `next_child_label` checks (zero / wrap) **do not carry over**
  — ids are CLC-derived, so there is no per-parent counter.

*delete(N)* — source is not root; **missing source → no-op** (global rule above);
otherwise `DeletePrefix` removes the whole container and `Delete` the record.

## 5. Trade-off (stated once)

Gains: **one-level listing**, **subtree-as-proof-unit locality**, **O(depth)
move and delete**. Cost: **name lookup `/a/b/c` is level-by-level** — ids are
content-derived, not names, and names are encrypted, so resolving a path means
scanning each level's `/info` and decrypting (or adding a name index, §7). With a
stored handle (the id chain) lookup is direct. There is **no** listing-vs-move
exclusivity here: `MovePrefix` is what removes it.

## 6. Implementation outline

**[`PLAN_TREE_FS_KEYMODEL.md`](../../PLAN_TREE_FS_KEYMODEL.md) is the authoritative,
agent-executable plan** (stage-by-stage Touches / Tests-to-add / runnable Gate /
Commit). This is the one-line map; the plan owns the detail and the decisions
(name-encryption/MIME deferred, `content_hash` form, etc. — see plan §0). Follow-on
to Phase B; branch `trev/tree-fs-keymodel` off `trev/tree-fs-mrt`.

- **K0 — prerequisites & spike** *(blocks the rest)*. Raise the codec
  `MAX_FS_KEY_LEN` (64 → 4096; no `changelog::MAX_KEY_LEN` change — §2), and **prove
  a hand-built `MovePrefix`/`DeletePrefix` change end-to-end** (correctness only;
  efficiency is observed at K5). Halts the plan if the prefix op can't prove.
- **K1 — codec.** `Inode` + the `/dir`/`/info` key functions (`derive_inode_id`,
  `encode_record_key`, `encode_container_prefix`, `encode_children_listing_prefix`
  = `CONTAINER ‖ /info`, `decode_record_key`) in both codec files.
- **K2 — verifiers.** `tree_fs_create/rename/move/delete` per §4 (move →
  `MovePrefix`, delete → `DeletePrefix`, all preconditions); shape tests assert the
  emitted `write_steps`.
- **K3 — SDK.** `FsHandle = Vec<[u8;32]>`; `submit_tree_fs_*` (create returns the
  accepted id) + raw-read helpers.
- **K4 — demo + wire + model.** `files_tree` API, the breaking `FsHandleWire`
  contract (`string[]` hex), `TreeFsModel`/`fs_consistency` + MIME, empty-root `[]`.
- **K5 — bench.** `fs_tree_*` rows on the new codec; move/delete cycles must land
  **below** the flat baseline (where the O(depth) payoff shows up).

## 7. Open knobs
- **Tag width** — readable `/dir`/`/info` (depth ≈112) vs compact `//`/`/i`
  (≈119). Use readable.
- **Name index** — optionally add `CONTAINER(D) ‖ /name ‖ Hkey(name) → h_child`
  (a keyed, client-computable hash of the plaintext name) for O(1) name→child
  resolution without scanning. Adds one key + write per node; defer unless
  name-lookup latency matters.
- **mtime on move** — whether move bumps the moved node's `mtime` (the §4 lowering
  assumes yes; drop the value `Put` if not).

## 8. Out of scope
- Migrating shipped flat-scheme records to this model (greenfield; the flat
  backend is a prototype with no persisted data to preserve).
- The Tauri wire/UI integration (`PLAN_TAURI_TREE_FS.md`) — orthogonal to the key
  model. Note that a production **proven** raw read does **not exist yet**:
  `WebSocketTransport::raw_read` is still the unsupported default and
  `database.proto` has no raw-read request (that is `PLAN_TAURI_TREE_FS.md`
  stage T-A). Whenever it is built it serves whichever key model is in place;
  this design neither provides nor depends on it.
