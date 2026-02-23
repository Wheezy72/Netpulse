-- Migration: RBAC enum update + routers.if_indexes JSONB + audit_logs table
-- Safe to run multiple times in PostgreSQL.

BEGIN;

-- 1) Normalize role values
ALTER TABLE users
  ALTER COLUMN role TYPE text USING role::text;

UPDATE users
SET role = 'operator'
WHERE role IS NULL OR role = 'viewer';

-- 2) Recreate enum type with the new values
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
    DROP TYPE userrole;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
    DROP TYPE user_role;
  END IF;
END
$$;

CREATE TYPE user_role AS ENUM ('admin', 'operator');

ALTER TABLE users
  ALTER COLUMN role TYPE user_role USING role::user_role,
  ALTER COLUMN role SET DEFAULT 'operator',
  ALTER COLUMN role SET NOT NULL;

-- 3) routers.if_indexes -> jsonb (if table exists)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'routers' AND column_name = 'if_indexes'
  ) THEN
    ALTER TABLE routers
      ALTER COLUMN if_indexes TYPE jsonb USING COALESCE(if_indexes, '[]')::jsonb,
      ALTER COLUMN if_indexes SET DEFAULT '[]'::jsonb;
  END IF;
END
$$;

-- 4) Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  method VARCHAR(10) NOT NULL,
  path VARCHAR(512) NOT NULL,
  action VARCHAR(255) NOT NULL,
  ip_address VARCHAR(64),
  details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs(created_at);

COMMIT;
