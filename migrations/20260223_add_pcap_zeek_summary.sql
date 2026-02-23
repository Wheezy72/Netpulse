-- NetPulse: Zeek summary metadata for PCAP files
--
-- Adds a nullable JSON column to store summarized Zeek output for a PCAP.
--
-- Written for PostgreSQL.
-- Safe to re-run: uses IF NOT EXISTS.

BEGIN;

ALTER TABLE pcap_files
    ADD COLUMN IF NOT EXISTS zeek_summary JSON NULL;

COMMIT;
