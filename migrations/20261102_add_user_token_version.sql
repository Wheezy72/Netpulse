-- Session revocation: every token records the version it was issued under, and
-- bumping this column invalidates all of them at once. Applied automatically at
-- startup on PostgreSQL; run by hand for scripted upgrades:
--
--   psql "$DATABASE_URL" -f migrations/20261102_add_user_token_version.sql

ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN users.token_version IS
  'Incremented to revoke every previously issued session token for this account.';