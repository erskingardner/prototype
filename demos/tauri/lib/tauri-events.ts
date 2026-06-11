import {
  listen,
  type EventCallback,
  type EventName,
  type Options,
  type UnlistenFn,
} from "@tauri-apps/api/event";

function runUnlisten(unlisten: UnlistenFn) {
  try {
    Promise.resolve(unlisten()).catch((err) => {
      console.warn("[tauri-events] unlisten failed:", err);
    });
  } catch (err) {
    console.warn("[tauri-events] unlisten failed:", err);
  }
}

export function listenSafely<T>(
  event: EventName,
  handler: EventCallback<T>,
  options?: Options
): () => void {
  let disposed = false;
  let unlisten: UnlistenFn | null = null;

  listen<T>(event, handler, options)
    .then((fn) => {
      if (disposed) {
        runUnlisten(fn);
      } else {
        unlisten = fn;
      }
    })
    .catch((err) => {
      console.warn(`[tauri-events] listen failed for ${event}:`, err);
    });

  return () => {
    if (disposed) return;
    disposed = true;
    if (unlisten) {
      runUnlisten(unlisten);
      unlisten = null;
    }
  };
}
