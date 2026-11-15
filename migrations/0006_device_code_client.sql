-- Who asked for each device code (a keyed hash of the caller's address), so one caller can hold
-- only a few unapproved codes at a time. Rows live ten minutes at most.
ALTER TABLE wb_device_codes ADD COLUMN client TEXT;
