"use client";

import { useEffect, useState, useCallback, useMemo, useRef, type DragEvent } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import { listen } from "@tauri-apps/api/event";
import * as api from "@/lib/api";
import {
  INODE_FOLDER,
  INODE_FILE,
  ROOT_HANDLE,
  handleKey,
  type FsHandleWire,
  type TreeInodeWithAuthor,
} from "@/lib/types";
import { FileTypeIcon, formatSize } from "./message-input";

const IMAGE_MIMES = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp",
  "image/svg+xml", "image/bmp", "image/x-icon",
]);
const VIDEO_MIMES = new Set(["video/mp4", "video/webm", "video/ogg", "video/quicktime"]);

function getExt(name: string): string {
  return name.split(".").pop()?.toLowerCase() ?? "";
}

/** True if `prefix` is a (non-strict) prefix of `handle` — i.e. `handle` is at
 *  or inside the subtree rooted at `prefix`. */
function isHandlePrefix(prefix: FsHandleWire, handle: FsHandleWire): boolean {
  return prefix.length <= handle.length && prefix.every((label, i) => label === handle[i]);
}

/** Rebase `target` from the moved subtree `oldRoot` onto `newRoot`. Returns
 *  `target` unchanged when it does not point inside the moved subtree. A move
 *  rebases the moved root's handle and every descendant handle (the handle is
 *  the hierarchical position), so any handle the UI still holds must be rebased.
 */
function rebaseHandle(
  target: FsHandleWire,
  oldRoot: FsHandleWire,
  newRoot: FsHandleWire,
): FsHandleWire {
  if (!isHandlePrefix(oldRoot, target)) return target;
  return [...newRoot, ...target.slice(oldRoot.length)];
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function Files() {
  // The tree browser keeps its own listing in local state (the shared store's
  // `inodes` is typed for the table backend). Refreshed by every mutating action.
  const [inodes, setInodes] = useState<TreeInodeWithAuthor[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // In-app confirmation (no Tauri dialog plugin — works in any webview without a
  // permission/ACL rebuild). `askConfirm` resolves when the user clicks a button.
  const [confirmDialog, setConfirmDialog] = useState<
    { message: string; title: string; resolve: (ok: boolean) => void } | null
  >(null);
  function askConfirm(message: string, title: string): Promise<boolean> {
    return new Promise((resolve) => setConfirmDialog({ message, title, resolve }));
  }
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");
  // Rename target keyed by handle string (handles are arrays, not stable refs).
  const [renamingKey, setRenamingKey] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  // Navigation stack: folder path of { handle, name }. The tree backend's inode
  // identity is a hierarchical handle (FsHandleWire), with the root as [].
  const [pathStack, setPathStack] = useState<{ id: FsHandleWire; name: string }[]>([
    { id: ROOT_HANDLE, name: "Files" },
  ]);
  // File cache for lightbox blob URLs
  const [fileCache, setFileCache] = useState<Record<string, string>>({});
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);
  const [savingHash, setSavingHash] = useState<string | null>(null);
  // Drag-and-drop move state. `draggedRef` holds the node being dragged;
  // `dropTargetKey` highlights the folder/breadcrumb under the cursor.
  const draggedRef = useRef<TreeInodeWithAuthor | null>(null);
  const [draggingKey, setDraggingKey] = useState<string | null>(null);
  const [dropTargetKey, setDropTargetKey] = useState<string | null>(null);

  const currentParent = pathStack[pathStack.length - 1].id;

  // Load inodes for current directory
  const refresh = useCallback(async () => {
    try {
      const items = await api.listInodesTree(currentParent);
      setInodes(items);
      setError(null);
    } catch (e: any) {
      // Surface (don't swallow): a failing proven read here means the client's
      // data commitment diverged from the server — which otherwise just looks
      // like "the write didn't take" (a stale listing).
      setError(`Listing failed: ${typeof e === "string" ? e : (e?.message ?? String(e))}`);
    }
    // currentParent is an array; key the effect on its stable string form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handleKey(currentParent)]);

  useEffect(() => { refresh(); }, [refresh]);

  // Refresh when broadcast arrives (e.g. another user uploaded)
  useEffect(() => {
    const unlisten = listen("space-updated", () => { refresh(); });
    return () => { unlisten.then((fn) => fn()); };
  }, [refresh]);

  // Separate folders and files
  const folders = useMemo(() => inodes.filter((n) => n.type === INODE_FOLDER), [inodes]);
  const files = useMemo(() => inodes.filter((n) => n.type === INODE_FILE), [inodes]);

  // Previewable files (for lightbox navigation)
  const previewableFiles = useMemo(
    () => files.filter((f) => IMAGE_MIMES.has(f.mime_type) || VIDEO_MIMES.has(f.mime_type) || f.mime_type === "application/pdf" || f.mime_type.startsWith("audio/")),
    [files],
  );

  // Breadcrumbs from path stack
  const breadcrumbs = pathStack;

  // Ensure a file is loaded into cache (for lightbox)
  const ensureFileLoaded = useCallback(async (hash: string, mimeType: string) => {
    if (!hash || fileCache[hash]) return;
    try {
      const bytes = await api.downloadFile(hash);
      const blob = new Blob([new Uint8Array(bytes)], { type: mimeType });
      setFileCache((prev) => ({ ...prev, [hash]: URL.createObjectURL(blob) }));
    } catch { /* ignore */ }
  }, [fileCache]);

  function navigateToFolder(folderId: FsHandleWire, folderName: string) {
    setPathStack((prev) => [...prev, { id: folderId, name: folderName }]);
  }

  function navigateToBreadcrumb(index: number) {
    setPathStack((prev) => prev.slice(0, index + 1));
  }

  async function handleUpload() {
    const selected = await open({ multiple: true, title: "Upload files" });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    if (paths.length === 0) return;

    setUploading(true);
    setError(null);
    try {
      await api.uploadInodesTree(paths, currentParent);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function handleDownload(fileHash: string, filename: string) {
    setError(null);
    try {
      const dest = await save({ title: "Save file", defaultPath: filename });
      if (!dest) return;
      setSavingHash(fileHash);
      const data = await api.downloadFile(fileHash);
      await writeFile(dest, new Uint8Array(data));
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Download failed");
    } finally {
      setSavingHash(null);
    }
  }

  async function handleDelete(id: FsHandleWire, name: string, isFolder: boolean) {
    const msg = isFolder
      ? `Delete folder "${name}" and all its contents? This cannot be undone.`
      : `Delete "${name}"? This cannot be undone.`;
    try {
      const ok = await askConfirm(msg, isFolder ? "Delete folder" : "Delete file");
      if (!ok) return;
      const deleted = await api.deleteInodeTree(id);
      if (!deleted) {
        // rows_affected == 0: the server's verifier read the target as absent.
        setError(`Delete had no effect: "${name}" was not found on the server.`);
      }
      await refresh();
    } catch (e: any) {
      setError(`Delete failed: ${typeof e === "string" ? e : (e?.message ?? String(e))}`);
    }
  }

  async function handleCreateFolder() {
    const name = newFolderName.trim();
    if (!name || name.includes("/")) return;
    setCreatingFolder(false);
    setNewFolderName("");
    try {
      await api.createFolderInodeTree(currentParent, name);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Create folder failed");
    }
  }

  async function handleRename(id: FsHandleWire) {
    const name = renameValue.trim();
    if (!name) return;
    try {
      await api.renameInodeTree(id, name);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Rename failed");
    } finally {
      setRenamingKey(null);
      setRenameValue("");
    }
  }

  // Move `node` into the directory at handle `dest` (drag-and-drop). A move
  // rebases the moved root's handle and every descendant handle, so we consume
  // MoveInodeResult.new_id to rebase any visible handle (the breadcrumb path)
  // before refreshing; stale pre-move handles are dropped.
  async function handleMove(node: TreeInodeWithAuthor, dest: FsHandleWire) {
    const nodeK = handleKey(node.id);
    // No-ops: drop onto itself, into the current parent, or into own subtree.
    if (nodeK === handleKey(dest)) return;
    if (handleKey(node.parent_id) === handleKey(dest)) return;
    if (isHandlePrefix(node.id, dest)) return;
    setError(null);
    try {
      const result = await api.moveInodeTree(node.id, dest);
      if (result.moved && result.new_id) {
        const newId = result.new_id;
        setPathStack((prev) =>
          prev.map((bc) => ({ ...bc, id: rebaseHandle(bc.id, node.id, newId) })),
        );
        if (renamingKey === nodeK) setRenamingKey(null);
      }
      await refresh();
    } catch (e: any) {
      setError(`Move failed: ${typeof e === "string" ? e : (e?.message ?? String(e))}`);
    }
  }

  // ─── Drag-and-drop handlers ─────────────────────────────────────────────
  function onRowDragStart(node: TreeInodeWithAuthor) {
    draggedRef.current = node;
    setDraggingKey(handleKey(node.id));
  }

  function onRowDragEnd() {
    draggedRef.current = null;
    setDraggingKey(null);
    setDropTargetKey(null);
  }

  // A folder/breadcrumb at handle `dest` accepts the drop unless it is the
  // dragged node itself, its current parent, or inside its own subtree.
  function canDropOn(dest: FsHandleWire): boolean {
    const node = draggedRef.current;
    if (!node) return false;
    if (handleKey(node.id) === handleKey(dest)) return false;
    if (handleKey(node.parent_id) === handleKey(dest)) return false;
    return !isHandlePrefix(node.id, dest);
  }

  function onDropTargetOver(e: DragEvent, dest: FsHandleWire, key: string) {
    if (!canDropOn(dest)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    if (dropTargetKey !== key) setDropTargetKey(key);
  }

  function onDropTargetLeave(key: string) {
    if (dropTargetKey === key) setDropTargetKey(null);
  }

  function onDropTarget(e: DragEvent, dest: FsHandleWire) {
    e.preventDefault();
    const node = draggedRef.current;
    setDropTargetKey(null);
    setDraggingKey(null);
    draggedRef.current = null;
    if (node) handleMove(node, dest);
  }

  function openPreview(file: TreeInodeWithAuthor) {
    const idx = previewableFiles.findIndex((f) => handleKey(f.id) === handleKey(file.id));
    if (idx >= 0) {
      setLightboxIndex(idx);
    }
  }

  function isPreviewable(mime: string): boolean {
    return IMAGE_MIMES.has(mime) || VIDEO_MIMES.has(mime) || mime === "application/pdf" || mime.startsWith("audio/");
  }

  const isEmpty = folders.length === 0 && files.length === 0;

  return (
    <div className="files-container">
      <div className="files-header">
        <div className="files-breadcrumbs">
          {breadcrumbs.map((bc, i) => {
            const bcKey = "bc:" + handleKey(bc.id) + ":" + i;
            const isDropTarget = dropTargetKey === bcKey;
            return (
              <span key={bcKey}>
                {i > 0 && <span className="files-bc-sep">/</span>}
                {i < breadcrumbs.length - 1 ? (
                  <button
                    className={`files-bc-btn ${isDropTarget ? "files-drop-target" : ""}`}
                    onClick={() => navigateToBreadcrumb(i)}
                    onDragOver={(e) => onDropTargetOver(e, bc.id, bcKey)}
                    onDragLeave={() => onDropTargetLeave(bcKey)}
                    onDrop={(e) => onDropTarget(e, bc.id)}
                  >
                    {bc.name}
                  </button>
                ) : (
                  <span className="files-bc-current">{bc.name}</span>
                )}
              </span>
            );
          })}
        </div>
        <div className="files-header-actions">
          <button
            className="files-newfolder-btn"
            onClick={() => setCreatingFolder(!creatingFolder)}
            title="New Folder"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style={{marginRight:4,verticalAlign:"middle"}}><path d="M1 3v10h14V5H7.5L6 3H1zm1 1h3.3l1.5 2H14v6H2V4z"/></svg>
            New Folder
          </button>
          <button className="files-upload-btn" onClick={handleUpload} disabled={uploading}>
            {uploading ? "Uploading\u2026" : (<><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style={{marginRight:4,verticalAlign:"middle"}}><path d="M8 1L3 6h3v5h4V6h3L8 1z"/><path d="M2 13v1h12v-1H2z"/></svg>Upload</>)}
          </button>
        </div>
      </div>

      {creatingFolder && (
        <div className="files-newfolder-input">
          <input
            autoFocus
            placeholder="Folder name"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreateFolder();
              if (e.key === "Escape") { setCreatingFolder(false); setNewFolderName(""); }
            }}
          />
          <button onClick={handleCreateFolder} disabled={!newFolderName.trim()}>Create</button>
          <button onClick={() => { setCreatingFolder(false); setNewFolderName(""); }}>Cancel</button>
        </div>
      )}

      {error && (
        <div className="files-error">
          <span>{error}</span>
          <button onClick={() => setError(null)}>&times;</button>
        </div>
      )}

      {confirmDialog && (
        <div
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)",
            display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
          }}
          onClick={() => { confirmDialog.resolve(false); setConfirmDialog(null); }}
        >
          <div
            style={{
              background: "var(--background, #1e1e1e)", color: "var(--foreground, #eee)",
              padding: "1.25rem 1.5rem", borderRadius: 8, maxWidth: "26rem",
              boxShadow: "0 10px 40px rgba(0,0,0,0.4)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ margin: "0 0 0.5rem" }}>{confirmDialog.title}</h3>
            <p style={{ margin: "0 0 1.25rem" }}>{confirmDialog.message}</p>
            <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}>
              <button onClick={() => { confirmDialog.resolve(false); setConfirmDialog(null); }}>
                Cancel
              </button>
              <button
                style={{ background: "#dc2626", color: "#fff", border: "none", padding: "0.4rem 0.9rem", borderRadius: 4 }}
                onClick={() => { confirmDialog.resolve(true); setConfirmDialog(null); }}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {isEmpty ? (
        <div className="files-empty">
          <p>No files here yet.</p>
          <p className="files-empty-hint">Upload files or create a folder to get started.</p>
        </div>
      ) : (
        <div className="files-list">
          {/* Folders first */}
          {folders.map((node) => {
            const nodeK = handleKey(node.id);
            const rowClass =
              "files-row files-folder-row" +
              (draggingKey === nodeK ? " files-row-dragging" : "") +
              (dropTargetKey === nodeK ? " files-drop-target" : "");
            return (
            <div
              key={nodeK}
              className={rowClass}
              draggable
              onDragStart={() => onRowDragStart(node)}
              onDragEnd={onRowDragEnd}
              onDragOver={(e) => onDropTargetOver(e, node.id, nodeK)}
              onDragLeave={() => onDropTargetLeave(nodeK)}
              onDrop={(e) => onDropTarget(e, node.id)}
            >
              <span
                className="files-icon files-folder-icon"
                onClick={() => navigateToFolder(node.id, node.name)}
              >
                <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor"><path d="M1 3v10h14V5H7.5L6 3H1zm1 1h3.3l1.5 2H14v6H2V4z"/></svg>
              </span>
              <div className="files-info" onClick={() => navigateToFolder(node.id, node.name)}>
                {renamingKey === nodeK ? (
                  <input
                    className="files-rename-input"
                    autoFocus
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleRename(node.id);
                      if (e.key === "Escape") { setRenamingKey(null); setRenameValue(""); }
                    }}
                    onBlur={() => { setRenamingKey(null); setRenameValue(""); }}
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <span className="files-name">{node.name}</span>
                )}
                <span className="files-meta">
                  {node.author_name} &middot; {formatDate(node.ctime)}
                </span>
              </div>
              <div className="files-actions">
                <button
                  className="files-action-btn"
                  title="Rename"
                  onClick={(e) => { e.stopPropagation(); setRenamingKey(nodeK); setRenameValue(node.name); }}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M12.1 1.3a1 1 0 0 1 1.4 0l1.2 1.2a1 1 0 0 1 0 1.4l-8.5 8.5L3 13l.6-3.2 8.5-8.5zM11.4 4L5 10.4l-.3 1.6 1.6-.3L12.7 5.3 11.4 4z"/></svg>
                </button>
                <button
                  className="files-action-btn files-delete-btn"
                  title="Delete folder"
                  onClick={(e) => { e.stopPropagation(); handleDelete(node.id, node.name, true); }}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M5 2V1h6v1h4v1H1V2h4zm0 2h6l-.5 10h-5L5 4zm2 1.5v7h2v-7H7z"/></svg>
                </button>
              </div>
            </div>
            );
          })}

          {/* Files */}
          {files.map((node) => {
            const nodeK = handleKey(node.id);
            const canPreview = isPreviewable(node.mime_type);
            const isImage = IMAGE_MIMES.has(node.mime_type);
            const thumbUrl = isImage ? fileCache[node.file_hash] : null;

            // Lazy-load thumbnail for images
            if (isImage && !fileCache[node.file_hash] && node.file_hash) {
              ensureFileLoaded(node.file_hash, node.mime_type);
            }

            return (
              <div
                key={nodeK}
                className={`files-row${draggingKey === nodeK ? " files-row-dragging" : ""}`}
                draggable
                onDragStart={() => onRowDragStart(node)}
                onDragEnd={onRowDragEnd}
              >
                <span
                  className={`files-icon ${canPreview ? "files-icon-clickable" : ""}`}
                  onClick={() => canPreview && openPreview(node)}
                  title={canPreview ? "Preview" : undefined}
                >
                  {thumbUrl ? (
                    <img className="files-thumb" src={thumbUrl} alt={node.name} />
                  ) : (
                    <FileTypeIcon ext={getExt(node.name)} />
                  )}
                </span>
                <div className="files-info">
                  {renamingKey === nodeK ? (
                    <input
                      className="files-rename-input"
                      autoFocus
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleRename(node.id);
                        if (e.key === "Escape") { setRenamingKey(null); setRenameValue(""); }
                      }}
                      onBlur={() => { setRenamingKey(null); setRenameValue(""); }}
                    />
                  ) : (
                    <span
                      className={`files-name ${canPreview ? "files-name-clickable" : ""}`}
                      onClick={() => canPreview && openPreview(node)}
                    >
                      {node.name}
                    </span>
                  )}
                  <span className="files-meta">
                    {formatSize(node.size)} &middot; {node.author_name} &middot; {formatDate(node.ctime)}
                  </span>
                </div>
                <div className="files-actions">
                  <button
                    className="files-action-btn"
                    title="Rename"
                    onClick={() => { setRenamingKey(nodeK); setRenameValue(node.name); }}
                  >
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M12.1 1.3a1 1 0 0 1 1.4 0l1.2 1.2a1 1 0 0 1 0 1.4l-8.5 8.5L3 13l.6-3.2 8.5-8.5zM11.4 4L5 10.4l-.3 1.6 1.6-.3L12.7 5.3 11.4 4z"/></svg>
                  </button>
                  {canPreview && (
                    <button
                      className="files-action-btn"
                      title="Preview"
                      onClick={() => openPreview(node)}
                    >
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3C3 3 0 8 0 8s3 5 8 5 8-5 8-5-3-5-8-5zm0 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-4.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/></svg>
                    </button>
                  )}
                  <button
                    className="files-action-btn"
                    title="Download"
                    disabled={savingHash === node.file_hash}
                    onClick={() => handleDownload(node.file_hash, node.name)}
                  >
                    {savingHash === node.file_hash ? (
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" className="spin"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="28" strokeDashoffset="8"/></svg>
                    ) : (
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1v9M8 10l-3-3M8 10l3-3"/><path d="M8 1v9" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M5 7l3 3 3-3" stroke="currentColor" strokeWidth="2" fill="none" strokeLinejoin="round"/><path d="M2 13v1h12v-1H2z"/></svg>
                    )}
                  </button>
                  <button
                    className="files-action-btn files-delete-btn"
                    title="Delete"
                    onClick={() => handleDelete(node.id, node.name, false)}
                  >
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M5 2V1h6v1h4v1H1V2h4zm0 2h6l-.5 10h-5L5 4zm2 1.5v7h2v-7H7z"/></svg>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Lightbox */}
      {lightboxIndex !== null && previewableFiles[lightboxIndex] && (
        <FileLightbox
          files={previewableFiles}
          startIndex={lightboxIndex}
          fileCache={fileCache}
          onClose={() => setLightboxIndex(null)}
          onSave={(f) => handleDownload(f.file_hash, f.name)}
          savingHash={savingHash}
          ensureFileLoaded={ensureFileLoaded}
        />
      )}
    </div>
  );
}

// ─── File Lightbox ──────────────────────────────────────────────────────────

function FileLightbox({ files, startIndex, fileCache, onClose, onSave, savingHash, ensureFileLoaded }: {
  files: TreeInodeWithAuthor[];
  startIndex: number;
  fileCache: Record<string, string>;
  onClose: () => void;
  onSave: (f: TreeInodeWithAuthor) => void;
  savingHash: string | null;
  ensureFileLoaded: (hash: string, mime: string) => void;
}) {
  const [index, setIndex] = useState(startIndex);
  const node = files[index];
  const total = files.length;
  const blobUrl = fileCache[node.file_hash] ?? null;

  useEffect(() => { ensureFileLoaded(node.file_hash, node.mime_type); }, [node.file_hash, node.mime_type]);

  // Preload adjacent
  useEffect(() => {
    if (index > 0) ensureFileLoaded(files[index - 1].file_hash, files[index - 1].mime_type);
    if (index < total - 1) ensureFileLoaded(files[index + 1].file_hash, files[index + 1].mime_type);
  }, [index, files, total]);

  const goPrev = useCallback(() => setIndex((i) => Math.max(0, i - 1)), []);
  const goNext = useCallback(() => setIndex((i) => Math.min(total - 1, i + 1)), [total]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowLeft") goPrev();
      else if (e.key === "ArrowRight") goNext();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, goPrev, goNext]);

  const isImage = IMAGE_MIMES.has(node.mime_type);
  const isVideo = VIDEO_MIMES.has(node.mime_type);
  const isPdf = node.mime_type === "application/pdf";
  const isAudio = node.mime_type.startsWith("audio/");

  return (
    <div className="lightbox-backdrop" onClick={onClose}>
      <div className="lightbox-container" onClick={(e) => e.stopPropagation()}>
        <div className="lightbox-header">
          <span className="lightbox-filename" title={node.name}>{node.name}</span>
          {total > 1 && (
            <span className="lightbox-counter">{index + 1} / {total}</span>
          )}
          <span className="lightbox-meta">{formatSize(node.size)} &middot; {node.author_name}</span>
          <div className="lightbox-actions">
            <button className="lightbox-btn" onClick={() => onSave(node)} disabled={savingHash === node.file_hash} title="Save to disk">
              {savingHash === node.file_hash ? (
                <div className="attachment-loading-spinner small" />
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                  stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
                </svg>
              )}
            </button>
            <button className="lightbox-btn lightbox-close" onClick={onClose} title="Close (Esc)">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </div>

        <div className="lightbox-content">
          {total > 1 && index > 0 && (
            <button className="lightbox-nav lightbox-nav-prev" onClick={goPrev} title="Previous">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
            </button>
          )}
          {total > 1 && index < total - 1 && (
            <button className="lightbox-nav lightbox-nav-next" onClick={goNext} title="Next">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          )}

          {!blobUrl ? (
            <div className="lightbox-loading"><div className="attachment-loading-spinner" /></div>
          ) : isImage ? (
            <img key={node.file_hash} src={blobUrl} alt={node.name} className="lightbox-image" />
          ) : isVideo ? (
            <video key={node.file_hash} controls autoPlay className="lightbox-video">
              <source src={blobUrl} type={node.mime_type} />
            </video>
          ) : isPdf ? (
            <iframe key={node.file_hash + "-lb"} src={blobUrl} className="lightbox-pdf" />
          ) : isAudio ? (
            <div className="lightbox-audio-wrapper">
              <FileTypeIcon ext={getExt(node.name)} />
              <audio key={node.file_hash} controls autoPlay className="lightbox-audio">
                <source src={blobUrl} type={node.mime_type} />
              </audio>
            </div>
          ) : (
            <div className="lightbox-unsupported">
              <FileTypeIcon ext={getExt(node.name)} />
              <p>Preview not available</p>
              <button className="lightbox-save-large" onClick={() => onSave(node)}>Save to view</button>
            </div>
          )}
        </div>

        {total > 1 && (
          <div className="lightbox-strip">
            {files.map((f, i) => (
              <button
                key={handleKey(f.id)}
                className={`lightbox-thumb ${i === index ? "lightbox-thumb-active" : ""}`}
                onClick={() => setIndex(i)}
              >
                {IMAGE_MIMES.has(f.mime_type) && fileCache[f.file_hash] ? (
                  <img src={fileCache[f.file_hash]} alt={f.name} />
                ) : (
                  <FileTypeIcon ext={getExt(f.name)} />
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
