-- When a token stops working (ISO 8601); NULL never expires, as before. Whiteboard login tokens
-- (src/whiteboard.ts) get one, so an approval made by mistake does not last forever.
ALTER TABLE tokens ADD COLUMN expires_at TEXT;
