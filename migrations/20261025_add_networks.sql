--25-10-2026 — remember networks and scope the device inventory to them.
--
-- Home networks reuse the same addresses, so devices were keyed by IP alone and
-- a second network's 192.168.1.10 overwrote the first one's row. A network row
-- is identified by subnet + gateway MAC; devices now carry network_id and an
-- address is unique only inside one network.
--
-- Existing devices keep network_id NULL and are adopted by the first discovery
-- sweep that matches them.
--
-- Run once:  psql "$DATABASE_URL" -f migrations/20261025_add_networks.sql

BEGIN;

CREATE TABLE IF NOT EXISTS networks (
    id          SERIAL PRIMARY KEY,
    key         VARCHAR(128) NOT NULL,
    name        VARCHAR(100) NOT NULL,
    cidr        VARCHAR(50)  NOT NULL DEFAULT '',
    gateway_ip  VARCHAR(64),
    gateway_mac VARCHAR(32),
    interface   VARCHAR(64),
    first_seen  TIMESTAMPTZ  DEFAULT now(),
    last_seen   TIMESTAMPTZ  DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_networks_key ON networks (key);

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL;

-- The old global unique index is what refused a second network's :.10.
DROP INDEX IF EXISTS ix_devices_ip_address;
CREATE INDEX IF NOT EXISTS ix_devices_ip_address ON devices (ip_address);
CREATE INDEX IF NOT EXISTS ix_devices_network_id ON devices (network_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_network_ip ON devices (network_id, ip_address);

COMMIT;
