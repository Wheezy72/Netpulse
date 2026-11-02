-- Two-factor authentication (RFC 6238) for existing installs.
--
-- create_all() cannot add columns to a table that already exists, so the app
-- applies these at startup as well (see _SESSION_SCHEMA_STATEMENTS in
-- app/main.py). This file is the same change for anyone migrating by hand.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_recovery_codes TEXT;

COMMENT ON COLUMN users.totp_secret IS
    'Base32 TOTP secret. Present during enrolment, required at sign-in once totp_enabled is true.';
COMMENT ON COLUMN users.totp_recovery_codes IS
    'JSON array of sha256 digests of unused recovery codes; each is consumed on use.';
