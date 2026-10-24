-- Artifacts: one row per shareable page. Content lives in R2 as content-addressed blobs
-- (blob/<sha256>); each version's manifest maps published paths to those blobs, so a
-- republish that changes one file copies nothing.
CREATE TABLE artifacts (
  id             TEXT PRIMARY KEY,           -- 20 chars [a-z0-9]: also the content-origin label
  owner          TEXT NOT NULL,              -- lowercased email
  title          TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  live_version   INTEGER NOT NULL,
  read_mode      TEXT NOT NULL DEFAULT 'owner' CHECK (read_mode IN ('owner','users','org','public')),
  read_users     TEXT NOT NULL DEFAULT '[]', -- JSON array of emails (mode 'users')
  write_users    TEXT NOT NULL DEFAULT '[]', -- JSON array of editor emails (any mode)
  pinned_version INTEGER,                    -- NULL = viewers follow live
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE INDEX artifacts_owner ON artifacts(owner, updated_at DESC);

CREATE TABLE versions (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  ver         INTEGER NOT NULL,
  author      TEXT NOT NULL,
  label       TEXT NOT NULL DEFAULT '',
  manifest    TEXT NOT NULL,                 -- JSON {path: {sha256, size, type}}
  created_at  TEXT NOT NULL,
  PRIMARY KEY (artifact_id, ver)
);

CREATE TABLE comments (
  id          TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  ver         INTEGER NOT NULL,
  author      TEXT NOT NULL,
  body        TEXT NOT NULL,
  resolved    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);
CREATE INDEX comments_artifact ON comments(artifact_id, created_at);

-- API tokens for the CLI and agents (mini, laptop). Only the SHA-256 is stored.
CREATE TABLE tokens (
  hash       TEXT PRIMARY KEY,
  owner      TEXT NOT NULL,
  label      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used  TEXT
);

-- Single-use login handoffs from the Access-protected login host.
CREATE TABLE handoffs (
  nonce   TEXT PRIMARY KEY,
  expires INTEGER NOT NULL
);
