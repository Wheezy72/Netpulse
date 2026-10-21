--20-10-2026 — collapse RBAC to two roles: ADMIN and VIEWER.
--
-- The application enum now only defines those two values, so any row still
-- holding OPERATOR or AUDITOR would fail to load. Postgres enum types cannot
-- drop a value in place, which is why the column is widened to text, remapped,
-- and then re-narrowed against a freshly created type.
--
-- Run once:  psql "$DATABASE_URL" -f migrations/20261020_users_role_admin_viewer.sql

BEGIN;

ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(16) USING role::text;

-- operator and auditor both become viewer: both were read-only in practice,
-- differing only by which scan endpoints answered403 for one of them.
UPDATE users SET role = 'VIEWER' WHERE role IN ('OPERATOR', 'AUDITOR');

DROP TYPE IF EXISTS user_role;
CREATE TYPE user_role AS ENUM ('ADMIN', 'VIEWER');

ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role;

COMMIT;
