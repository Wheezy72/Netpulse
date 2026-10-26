"""Unit tests for the hand-rolled SNMPv2c client.

Everything here runs without a socket: packets are built and parsed in process,
and ``walk`` is driven with a stubbed ``_request`` so its termination rules are
pinned down without a router on the other end.
"""
from __future__ import annotations

import pytest

from app.services import snmp_client as snmp


# ----------------------------------------------------------------- encoding


class TestEncoding:
    @pytest.mark.parametrize(
        "oid",
        [
            "1.3.6.1.2.1.4.22.1.3",
            "1.3.6.1.2.1.1.5.0",
            "1.3.6.1.4.1.2021.9.1.2.1",
            "1.3.6.1.4.1.8072.1.3.1",
            "1.2.3.1600000000",
        ],
    )
    def test_oid_roundtrip(self, oid: str) -> None:
        encoded = snmp.encode_oid(oid)
        tag, body, end = snmp._read_tlv(encoded, 0)
        assert tag == 0x06
        assert end == len(encoded)
        assert snmp.decode_oid(body) == oid

    @pytest.mark.parametrize("value", [0, 1, 127, 128, 32767, 32768, 0x7FFFFFFF])
    def test_integer_roundtrip(self, value: int) -> None:
        encoded = snmp.encode_integer(value)
        _, payload, _ = snmp._read_tlv(encoded, 0)
        assert int.from_bytes(payload, "big", signed=True) == value

    def test_rejects_impossible_oid(self) -> None:
        with pytest.raises(snmp.SnmpError):
            snmp.encode_oid("1")

    def test_build_message_carries_community_and_request_id(self) -> None:
        packet, request_id = snmp.build_message(["1.3.6.1.2.1.4.22.1.3"], "s3cret")
        assert b"s3cret" in packet
        assert 0 < request_id < 0x80000000

    def test_get_request_pdu_shape(self) -> None:
        message = snmp.encode_get_request(7, ["1.3.6.1.2.1.4.22.1.3"])
        assert message[0] == 0x30  # SEQUENCE
        # The PDU tag follows version + empty community.
        assert snmp._GET_REQUEST in message


# ----------------------------------------------------------------- decoding


def _seq(payload: bytes) -> bytes:
    return bytes([0x30]) + snmp._encode_length(len(payload)) + payload


def _octets(payload: bytes) -> bytes:
    return bytes([0x04]) + snmp._encode_length(len(payload)) + payload


def _response(oid: str, value: bytes, *, request_id: int = 42) -> bytes:
    varbind = _seq(snmp.encode_oid(oid) + _octets(value))
    pdu_body = snmp.encode_integer(request_id) + snmp.encode_integer(0) + snmp.encode_integer(0) + _seq(varbind)
    pdu = bytes([snmp._GET_RESPONSE]) + snmp._encode_length(len(pdu_body)) + pdu_body
    body = snmp.encode_integer(1) + _octets(b"public") + pdu
    return _seq(body)


class TestParsing:
    def test_parses_an_arp_table_row(self) -> None:
        oid = "1.3.6.1.2.1.4.22.1.3.1.192.168.1.100"
        packet = _response(oid, bytes([0x12, 0x3A, 0x1F, 0xAA, 0x7F, 0xEB]))
        request_id, varbinds = snmp.parse_response(packet)
        assert request_id == 42
        assert varbinds == [(oid, bytes([0x12, 0x3A, 0x1F, 0xAA, 0x7F, 0xEB]))]

    def test_rejects_a_non_snmp_packet(self) -> None:
        with pytest.raises(snmp.SnmpError):
            snmp.parse_response(b"\x30\x03\x00\x01\x02")

    def test_rejects_an_error_status(self) -> None:
        oid = "1.3.6.1.2.1.1.5.0"
        varbind = _seq(snmp.encode_oid(oid) + _octets(b"x"))
        pdu_body = snmp.encode_integer(1) + snmp.encode_integer(6) + snmp.encode_integer(2) + _seq(varbind)
        pdu = bytes([snmp._GET_RESPONSE]) + snmp._encode_length(len(pdu_body)) + pdu_body
        body = snmp.encode_integer(1) + _octets(b"public") + pdu
        with pytest.raises(snmp.SnmpError, match="error-status 6"):
            snmp.parse_response(_seq(body))


# -------------------------------------------------------------------- walk


def _walk_via_stub(monkeypatch: pytest.MonkeyPatch, replies: list[tuple[str, object]]) -> list:
    """Drive :func:`walk` over a fixed sequence of GETNEXT answers."""
    calls: list[str] = []

    def _fake_request(_host, _community, oids, **_kwargs):
        calls.append(oids[0])
        index = len(calls) - 1
        oid, value = replies[index]
        return [(oid, value)]

    monkeypatch.setattr(snmp, "_request", _fake_request)
    return snmp.walk("192.168.1.1", "1.3.6.1.2.1.4.22.1.3")


class TestWalk:
    def test_collects_the_subtree_then_stops(self, monkeypatch: pytest.MonkeyPatch) -> None:
        base = "1.3.6.1.2.1.4.22.1.3"
        results = _walk_via_stub(
            monkeypatch,
            [
                (f"{base}.1.192.168.1.1", b"\x8c\x44\xbb\x07\x6c\x10"),
                (f"{base}.1.192.168.1.100", b"\x12\x3a\x1f\xaa\x7f\xeb"),
                # Leaves the subtree: a row from the next column.
                ("1.3.6.1.2.1.4.22.1.4.1.192.168.1.1", 1),
            ],
        )
        assert len(results) == 2
        assert results[0][0].endswith("192.168.1.1")

    def test_stops_when_the_agent_does_not_advance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        base = "1.3.6.1.2.1.4.22.1.3"
        # A broken agent answering with the same OID forever must terminate
        # instead of walking the same entry until MAX_WALK_ENTRIES.
        results = _walk_via_stub(monkeypatch, [(f"{base}.1.192.168.1.1", b"\x01\x02\x03\x04\x05\x06")] * 50)
        assert len(results) == 1

    def test_empty_table_is_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(snmp, "_request", lambda *_args, **_kwargs: [("9.9.9", b"")])
        assert snmp.walk("192.168.1.1", "1.3.6.1.2.1.4.22.1.3") == []

    def test_error_from_the_agent_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*_args, **_kwargs):
            raise snmp.SnmpError("no reply from 192.168.1.1:161")

        monkeypatch.setattr(snmp, "_request", _boom)
        with pytest.raises(snmp.SnmpError, match="no reply"):
            snmp.walk("192.168.1.1", "1.3.6.1.2.1.4.22.1.3", retries=0)


# ------------------------------------------------------------- value helpers


class TestValueHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (bytes([0x12, 0x3A, 0x1F, 0xAA, 0x7F, 0xEB]), "123A1FAA7FEB"),
            ("12:3a:1f:aa:7f:eb", "123A1FAA7FEB"),
            ("12-3A-1F-AA-7F-EB", "123A1FAA7FEB"),
        ],
    )
    def test_mac_normalises_to_the_inventory_form(self, raw, expected) -> None:
        assert snmp.mac_to_str(raw) == expected

    @pytest.mark.parametrize("raw", [b"\x00" * 6, b"\xff" * 6, bytes([1, 2, 3]), "not-a-mac", None, 7])
    def test_implausible_macs_are_dropped(self, raw) -> None:
        assert snmp.mac_to_str(raw) is None

    def test_ip_forms(self) -> None:
        assert snmp.to_ip(bytes([192, 168, 1, 100])) == "192.168.1.100"
        assert snmp.to_ip("192.168.1.100") == "192.168.1.100"
        assert snmp.to_ip("10.0.0.256") is None
        assert snmp.to_ip(b"\x01\x02\x03") is None
        assert snmp.to_ip(None) is None
