-- 2026-10-19
-- Allow accounts to exist without an email address.
--
-- Registration now takes a username and an optional address; an account can
-- attach one later from Settings, which is what makes password recovery
-- possible for it. The unique index on email needs no change: Postgres permits
-- any number of NULLs under a unique index, unlike empty strings.
--
-- Run against an existing database volume:
--   psql "$DATABASE_URL" -f migrations/20261019_users_email_nullable.sql

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
