// The page `tack board` publishes: a read-only view of the Whiteboard snapshot beside it
// (board.whiteboard, a review-share/2 bundle). canvas/ is @dev.fast/canvas as published and
// vendor/ is React; `tack board` adds both. No top bar: its buttons act on a live review.
import { createElement as h } from "react";
import { createRoot } from "react-dom/client";
import { openShare, Whiteboard, WhiteboardProvider } from "@dev.fast/canvas";

const status = document.getElementById("status");
try {
  const res = await fetch("./board.whiteboard");
  if (!res.ok) throw new Error(`board.whiteboard: HTTP ${res.status}`);
  const view = await openShare(await res.json());
  document.title = view.title;
  createRoot(document.getElementById("root")).render(
    h(WhiteboardProvider, { data: view.data, host: view.host, settings: {} }, h(Whiteboard)),
  );
  status.remove();
  // Desktop opens a snapshot only when it names a repository to clone and quotes no
  // uncommitted changes.
  if (view.repository && !view.frozen) {
    const link = document.getElementById("download");
    link.download = `${view.title.replace(/[\\/:*?"<>|]+/g, " ").trim().slice(0, 80) || "board"}.whiteboard`;
    link.hidden = false;
  }
} catch (e) {
  status.textContent = `Could not open the board: ${e?.message ?? e}`;
}
