-- Host-offline alerting state: one notification per outage, cleared when the
-- host answers again. Applied automatically at startup on PostgreSQL; run by
-- hand for scripted upgrades:
--
--   psql "$DATABASE_URL" -f migrations/20261102_add_offline_alert_state.sql

ALTER TABLE devices ADD COLUMN IF NOT EXISTS offline_alert_sent BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN devices.offline_alert_sent IS
  'TRUE when the "host offline" alert has been sent for the current outage.';