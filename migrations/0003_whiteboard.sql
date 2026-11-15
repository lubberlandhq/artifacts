-- Whiteboard share hub (src/whiteboard.ts): Tack answers the share-service protocol that
-- `whiteboard login --origin` and `whiteboard share` speak, so a board's link is a Tack link.

-- Device logins in flight. `whiteboard login` gets a device code, a signed-in person approves
-- its user code on /device, and the next poll trades the device code for an API token.
CREATE TABLE wb_device_codes (
  device_hash TEXT PRIMARY KEY,           -- SHA-256 of the device code
  user_code   TEXT UNIQUE NOT NULL,
  email       TEXT,                       -- NULL until approved
  expires     INTEGER NOT NULL,           -- epoch seconds
  last_poll   INTEGER                     -- epoch milliseconds
);

-- One link per (owner, board). The link's capability is the only read control, so only its
-- hash is stored for look-ups; cap_sealed keeps it recoverable for the owner (AES-GCM).
CREATE TABLE wb_shares (
  id         TEXT PRIMARY KEY,            -- shareId, a UUID
  owner      TEXT NOT NULL,               -- lowercased email
  review_id  TEXT NOT NULL,
  title      TEXT NOT NULL,
  cap_hash   TEXT UNIQUE NOT NULL,
  cap_sealed TEXT NOT NULL,
  content_id TEXT UNIQUE NOT NULL,        -- 20 chars [a-z0-9]: the browser view's own origin label
  created_at INTEGER NOT NULL,            -- epoch milliseconds, as the protocol reports them
  UNIQUE (owner, review_id)
);

-- Immutable snapshots of a share; the bundle is in R2 at wb/<share id>/<revision id>.json.
CREATE TABLE wb_revisions (
  id         TEXT PRIMARY KEY,            -- a UUID
  share_id   TEXT NOT NULL REFERENCES wb_shares(id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  sender     TEXT NOT NULL,
  frozen     INTEGER NOT NULL DEFAULT 0,  -- quotes uncommitted changes: view only
  created_at INTEGER NOT NULL,
  UNIQUE (share_id, version)
);
CREATE INDEX wb_revisions_share ON wb_revisions(share_id, version DESC);

-- A retried upload (same request id) answers as the first one did.
CREATE TABLE wb_requests (
  owner      TEXT NOT NULL,
  request_id TEXT NOT NULL,
  share_id   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner, request_id)
);

-- Service settings an admin changes at run time. 'whiteboard_viewer' is the id of the artifact
-- holding the board viewer (`tack board-viewer`), which /s/<capability> pages render with.
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
