-- Router verification: mark devices the router's own tables list.
-- Applied automatically at startup on PostgreSQL; run by hand for scripted
-- upgrades:
--
--   psql "$DATABASE_URL" -f migrations/20261025_add_device_verification.sql

ALTER TABLE devices ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS verified_source VARCHAR(32);

COMMENT ON COLUMN devices.verified IS
  'TRUE when the router''s own ARP/DHCP tables listed this device on the last pull.';
COMMENT ON COLUMN devices.verified_at IS
  'When the router last confirmed the device; kept after verified drops.';
COMMENT ON COLUMN devices.verified_source IS
  'Source of the confirmation: snmp, routeros or dnsmasq.';