export interface UserInfo {
  user_id: number;
  user_name: string;
  ws_address: string;
  current_channel_id: number;
  current_channel_name: string;
}

export interface Channel {
  id: number | null;
  name: string;
  description: string | null;
}

export interface MessageWithUser {
  id: number | null;
  content: string;
  timestamp: number;
  author: string;
  user_id: number;
  thread_id: number;
  is_deleted_user: boolean;
}

export interface ReactionInfo {
  count: number;
  users: string[];
}

export type ReactionMap = Record<number, Record<string, ReactionInfo>>;

export interface UserRecord {
  id: number;
  name: string;
  status: "pending" | "member";
}

export interface Attachment {
  id: number | null;
  message_id: number;
  file_hash: string;
  filename: string;
  mime_type: string;
  size: number;
}

export interface TaskItem {
  key: string;
  title: string;
  done: boolean;
  position: number;
}

export interface CalendarItem {
  id: number | null;
  start_time: number;
  end_time: number;
  title: string;
  description: string;
}

export const INODE_FILE = 1;
export const INODE_FOLDER = 2;
export const ROOT_PARENT = 0;

export interface InodeWithAuthor {
  id: number | null;
  parent_id: number;
  author_id: number;
  name: string;
  type: number;
  size: number;
  ctime: number;
  mtime: number;
  mime_type: string;
  file_hash: string;
  author_name: string;
}

// ─── Tree filesystem backend (serialized hierarchical handles) ───────────────
//
// The tree backend's inode identity is a hierarchical handle serialized as an
// array of 64-char hex inode ids (the root-to-node id chain). The root handle
// is the empty array `[]`.

/** Wire representation of a hierarchical filesystem handle: hex inode ids,
 *  root is `[]`. */
export type FsHandleWire = string[];

/** Root handle for the tree filesystem backend. */
export const ROOT_HANDLE: FsHandleWire = [];

/** Stable string key for a handle (React keys, equality, map lookups). */
export function handleKey(handle: FsHandleWire): string {
  return handle.join("/");
}

export interface TreeInodeWithAuthor {
  id: FsHandleWire;
  parent_id: FsHandleWire;
  author_id: number;
  name: string;
  type: number;
  size: number;
  ctime: number;
  mtime: number;
  mime_type: string;
  file_hash: string;
  author_name: string;
}

/** Result of a tree move: the moved root's new handle, or null on no-op. */
export interface TreeMoveResult {
  moved: boolean;
  new_id: FsHandleWire | null;
}
