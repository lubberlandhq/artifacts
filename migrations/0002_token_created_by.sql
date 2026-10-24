-- Who minted a token. Equal to owner, except when an admin (ADMINS) mints one for another
-- publisher, e.g. a tenant's agent identity. The minter can list
-- and revoke it.
ALTER TABLE tokens ADD COLUMN created_by TEXT;
UPDATE tokens SET created_by = owner WHERE created_by IS NULL;
