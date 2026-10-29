-- NetPulse: drop the retired packet-capture tables
--
-- Packet capture is gone from the app: the capture service, its routes
-- (/captures, /pcaps, /packets), the Celery indexing task and the Packet
-- Browser UI were all removed. Nothing reads or writes these four tables any
-- more, so an upgraded install can reclaim the space.
--
-- Written for PostgreSQL.
--
-- Guarded so it is safe on any install, at any point in its history:
--
--   * Every drop uses IF EXISTS, so a fresh database (which never created these
--     tables, because their models are gone) passes through untouched.
--   * The whole file runs in one transaction: if any statement fails, the
--     database is left exactly as it was.
--   * Rows are counted first and reported with RAISE NOTICE, so the drop is
--     never silent about what it discarded.
--   * Tables are dropped children-first — pcap_packets before pcap_files,
--     packet_headers before packet_captures — so no foreign key can block it.
--   * Nothing outside this feature is named, and CASCADE is deliberately not
--     used: if some object you created depends on these tables, the migration
--     fails loudly instead of quietly dropping your object too. Add CASCADE by
--     hand once you know what that object is.
--
-- This is optional. The app runs fine with the tables still present; run this
-- only when you want the space back. Any .pcap files the old capture wrote to
-- disk live outside the database and are not touched — delete those yourself.
--
-- Safe to re-run.

BEGIN;

DO $$
DECLARE
    report text[] := ARRAY[]::text[];
    n bigint;
BEGIN
    IF to_regclass('pcap_packets') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM pcap_packets' INTO n;
        report := report || format('pcap_packets=%s rows', n);
    END IF;

    IF to_regclass('pcap_files') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM pcap_files' INTO n;
        report := report || format('pcap_files=%s rows', n);
    END IF;

    IF to_regclass('packet_headers') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM packet_headers' INTO n;
        report := report || format('packet_headers=%s rows', n);
    END IF;

    IF to_regclass('packet_captures') IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM packet_captures' INTO n;
        report := report || format('packet_captures=%s rows', n);
    END IF;

    IF cardinality(report) = 0 THEN
        RAISE NOTICE 'Packet-capture tables are already absent; nothing to drop.';
    ELSE
        RAISE NOTICE 'Dropping retired packet-capture tables (%)',
            array_to_string(report, ', ');
    END IF;
END;
$$;

DROP TABLE IF EXISTS pcap_packets;
DROP TABLE IF EXISTS pcap_files;
DROP TABLE IF EXISTS packet_headers;
DROP TABLE IF EXISTS packet_captures;

COMMIT;
