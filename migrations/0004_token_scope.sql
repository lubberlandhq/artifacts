-- What a token may be used for. NULL is the whole API, as before. 'whiteboard' is a token minted
-- by Whiteboard's device login (src/whiteboard.ts): it works on the share-hub routes only, so a
-- code approved by mistake hands over board sharing, not the person's artifacts.
ALTER TABLE tokens ADD COLUMN scope TEXT;
