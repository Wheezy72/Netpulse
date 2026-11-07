"""Tests for the proxy-ARP cleanup script's selection logic.

The script itself needs Postgres; what decides *which* rows to delete is a pure
function, so that is what these cover.
"""
from __future__ import annotations

from app.services.phantom_devices import DEFAULT_LIMIT, plan_purge

ROUTER_MAC = "8C:44:BB:07:6C:10"


def _row(device_id: int, ip: str, mac: str | None, *, network_id: int | None = 1,
         hostname: str | None = None, is_gateway: bool = False):
    return (device_id, network_id, mac, ip, hostname, is_gateway)


def test_default_limit_matches_discovery():
    """A looser rule here than in discovery would prune rows it still writes."""
    from app.services.device_discovery import PROXY_ARP_ADDRESS_LIMIT

    assert DEFAULT_LIMIT == PROXY_ARP_ADDRESS_LIMIT


def test_a_proxy_arp_clump_keeps_its_lowest_address():
    rows = [_row(1, "192.168.1.1", ROUTER_MAC, hostname="router", is_gateway=True)]
    rows += [_row(i, f"192.168.1.{i}", ROUTER_MAC) for i in range(2, 256)]

    clumps = plan_purge(rows)

    assert len(clumps) == 1
    clump = clumps[0]
    assert clump.keep_ip == "192.168.1.1"
    assert clump.keep_hostname == "router"
    assert clump.keep_is_gateway is True
    assert len(clump.delete_ids) == 254
    assert clump.rows == 255
    assert clump.first_dropped == "192.168.1.2"
    assert clump.last_dropped == "192.168.1.255"


def test_addresses_are_ordered_numerically_not_as_text():
    """.10 sorts before .9 in text, which would keep the wrong row."""
    rows = [_row(i, f"10.0.0.{i}", "AA:BB:CC:DD:EE:FF") for i in range(1, 13)]

    clump = plan_purge(rows)[0]

    assert clump.keep_ip == "10.0.0.1"


def test_a_normal_network_is_left_alone():
    rows = [
        _row(1, "192.168.1.1", "AA:AA:AA:AA:AA:01", is_gateway=True),
        _row(2, "192.168.1.2", "AA:AA:AA:AA:AA:02"),
        _row(3, "192.168.1.3", "AA:AA:AA:AA:AA:03"),
    ]

    assert plan_purge(rows) == []


def test_a_mac_at_the_limit_is_not_over_it():
    rows = [_row(i, f"192.168.1.{i}", ROUTER_MAC) for i in range(1, DEFAULT_LIMIT + 1)]

    assert plan_purge(rows) == []

    rows.append(_row(99, "192.168.1.99", ROUTER_MAC))
    assert len(plan_purge(rows)) == 1


def test_groups_are_per_network():
    """The same router MAC in two homes is two questions, not one clump."""
    rows = [_row(i, f"192.168.1.{i}", ROUTER_MAC, network_id=1) for i in range(1, 11)]
    rows += [_row(100 + i, f"192.168.1.{i}", ROUTER_MAC, network_id=2) for i in range(1, 11)]

    clumps = plan_purge(rows)

    assert [clump.network_id for clump in clumps] == [1, 2]
    assert all(len(clump.delete_ids) == 9 for clump in clumps)


def test_rows_without_a_mac_are_ignored():
    rows = [_row(i, f"192.168.1.{i}", None) for i in range(1, 30)]

    assert plan_purge(rows) == []


def test_mac_case_and_separators_do_not_split_a_clump():
    rows = [_row(i, f"192.168.1.{i}", ROUTER_MAC) for i in range(1, 7)]
    rows += [_row(50 + i, f"192.168.1.{10 + i}", "8c-44-bb-07-6c-10") for i in range(1, 6)]

    clumps = plan_purge(rows)

    assert len(clumps) == 1
    assert len(clumps[0].delete_ids) == 10


def test_limit_must_be_positive():
    import pytest

    with pytest.raises(ValueError):
        plan_purge([], limit=0)
