from __future__ import annotations

from app.services.cve_feed import (
    catalogue_updated,
    find_cve_matches,
    load_catalog,
    parse_version,
    version_in_range,
)


def _port(product: str, version: str, port: int = 80, service: str = "http") -> dict:
    return {
        "port": port,
        "protocol": "tcp",
        "service": service,
        "product": product,
        "version": version,
    }


def test_parse_version_keeps_patch_letters_and_levels():
    assert parse_version("2.4.49") == (2, 4, 49)
    assert parse_version("2.4.49 (Ubuntu)") == (2, 4, 49)
    # OpenSSH's patch level is what separates fixed from vulnerable.
    assert parse_version("7.1p2") == (7, 1, 2)
    # A letter revision sorts after the one before it.
    assert parse_version("1.0.1g") == (1, 0, 1, 7)
    assert parse_version("") is None
    assert parse_version(None) is None
    assert parse_version("unknown") is None


def test_version_range_bounds_are_half_open():
    entry = {"introduced": "2.4.49", "fixed": "2.4.50"}
    assert version_in_range((2, 4, 49), entry) is True
    assert version_in_range((2, 4, 50), entry) is False


def test_version_range_without_bounds_covers_everything():
    assert version_in_range((1, 0, 0), {"fixed": "1.1"}) is True
    assert version_in_range((1, 2), {"introduced": "1.1"}) is True
    assert version_in_range(None, {"fixed": "9.9"}) is False


def test_padded_and_short_versions_compare_equal():
    entry = {"introduced": "2.4", "fixed": "2.4.50"}
    assert version_in_range((2, 4, 0), entry) is True


def test_catalog_loads_and_is_not_empty():
    catalog = load_catalog()
    assert len(catalog) >= 10
    assert catalogue_updated()


def test_apache_2449_matches_path_traversal():
    matches = find_cve_matches([_port("Apache httpd", "2.4.49")])
    ids = {match.cve_id for match in matches}
    assert "CVE-2021-41773" in ids
    # The range for CVE-2021-44790 (2.4.0 - 2.4.52) also covers it.
    assert "CVE-2021-44790" in ids
    finding = next(match for match in matches if match.cve_id == "CVE-2021-41773")
    assert finding.port == 80
    assert "backport" in finding.detail
    assert finding.severity == "critical"


def test_patched_apache_matches_nothing():
    matches = find_cve_matches([_port("Apache httpd", "2.4.58")])
    assert matches == []


def test_openssh_user_enumeration_boundary():
    vulnerable = find_cve_matches([_port("OpenSSH", "7.6p1", 22, "ssh")])
    patched = find_cve_matches([_port("OpenSSH", "8.9p1", 22, "ssh")])
    assert "CVE-2018-15473" in {match.cve_id for match in vulnerable}
    assert "CVE-2018-15473" not in {match.cve_id for match in patched}


def test_unknown_product_is_never_flagged():
    assert find_cve_matches([_port("Acme Doorbell", "2.4.49", 80, "unknown")]) == []


def test_missing_version_is_skipped():
    assert find_cve_matches([_port("Apache httpd", "")]) == []


def test_same_cve_on_two_hosts_is_reported_once_per_port():
    matches = find_cve_matches(
        [_port("Apache httpd", "2.4.49", 80), _port("Apache httpd", "2.4.49", 80)]
    )
    keys = [(match.cve_id, match.port) for match in matches]
    assert len(keys) == len(set(keys))


def test_same_cve_is_reported_for_each_affected_port():
    matches = find_cve_matches(
        [_port("Apache httpd", "2.4.49", 80), _port("Apache httpd", "2.4.49", 8080)]
    )
    ports = {match.port for match in matches if match.cve_id == "CVE-2021-41773"}
    assert ports == {80, 8080}


def test_objects_as_well_as_dicts_are_accepted():
    class Observation:
        port = 443
        protocol = "tcp"
        service = "http"
        product = "nginx"
        version = "1.18.0"

    matches = find_cve_matches([Observation()])
    assert "CVE-2021-23017" in {match.cve_id for match in matches}
