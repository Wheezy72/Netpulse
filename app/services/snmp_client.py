"""A minimal SNMPv2c client.

Why this exists instead of a library:

  * The prebuilt ``snmp_arp_discovery.py`` imported ``pysnmp``, which is not in
    ``requirements.txt``, so running it raised ImportError at the first call.
  * Every router worth asking (MikroTik, Huawei, Ubiquiti, Cisco, ZTE, TP-Link
    business gear, OpenWrt) speaks SNMPv2c, and the only operations needed are
    a GET and a table walk. That is a few hundred bytes of BER plus a UDP
    socket — a whole ASN.1 stack is not worth the dependency.

Only what the verification path needs is implemented: v1/v2c over UDP, GET,
GETNEXT-walk, and value decoding for the types IP-MIB and DHCP-MIB use. There is
no SET (never needed, and writing to a router with a guessed community is
exactly the wrong default) and no v3 authentication framework.

The encoding helpers are module-level pure functions so they can be tested
without a socket; only :func:`_request` touches the network.
"""

from __future__ import annotations

import random
import select
import socket
import time
from typing import Any, List, Optional, Sequence, Tuple

__all__ = [
    "SnmpError",
    "build_message",
    "encode_get_request",
    "parse_response",
    "get",
    "walk",
    "mac_to_str",
    "to_ip",
]

DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 2.0
DEFAULT_RETRIES = 1
# A walk asks for the next entry until the answer leaves the subtree. An agent
# that refuses to advance (or a middlebox answering with a fixed value) would
# otherwise return the same OID forever.
MAX_WALK_ENTRIES = 8192

# GETBULK: how many rows to ask for per round trip, and how far to back off when
# the agent answers "tooBig". Walking a 300-entry ARP table one row at a time
# over a 1s-latency link took minutes; bulk makes it a handful of packets.
DEFAULT_BULK_REPETITIONS = 20
MIN_BULK_REPETITIONS = 1

# A chatty agent (traps, a monitoring system polling the same device) can keep
# the socket busy. Ignore a bounded number of foreign packets instead of
# extending the wait forever.
MAX_STRAY_PACKETS = 64

_GET_REQUEST = 0xA0
_GETNEXT_REQUEST = 0xA1
_GET_RESPONSE = 0xA2
_GETBULK_REQUEST = 0xA5

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_IP_ADDRESS = 0x40
_TAG_COUNTER32 = 0x41
_TAG_GAUGE32 = 0x42
_TAG_TIMETICKS = 0x43
_TAG_OPAQUE = 0x44
_TAG_COUNTER64 = 0x46


class SnmpError(Exception):
    """A failure to reach an agent or to make sense of its answer."""


# --------------------------------------------------------------------------
# BER encoding
# --------------------------------------------------------------------------


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


def encode_integer(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        length = max(1, (value.bit_length() + 8) // 8)
        payload = value.to_bytes(length, "big", signed=False)
        if payload[0] & 0x80:  # keep the sign bit clear
            payload = b"\x00" + payload
    return _tlv(_TAG_INTEGER, payload)


def encode_octet_string(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(_TAG_OCTET_STRING, value)


def encode_null() -> bytes:
    return bytes([_TAG_NULL, 0x00])


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID (``1.3.6.1.2.1.4.22.1.3``) as BER."""
    arcs = [int(part) for part in oid.strip().strip(".").split(".") if part != ""]
    if len(arcs) < 2:
        raise SnmpError(f"OID needs at least two arcs: {oid!r}")
    if arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise SnmpError(f"OID out of range: {oid!r}")

    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        groups: List[int] = [arc & 0x7F]
        arc >>= 7
        while arc:
            groups.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(groups))
    return _tlv(0x06, bytes(body))


def _encode_pdu(
    request_id: int,
    oids: Sequence[str],
    *,
    next_request: bool,
    bulk_repetitions: int = 0,
) -> bytes:
    varbinds = b"".join(_tlv(0x30, encode_oid(oid) + encode_null()) for oid in oids)
    if bulk_repetitions > 0:
        # GETBULK reuses the two integer fields: non-repeaters and
        # max-repetitions. Zero non-repeaters means every varbind is repeated.
        body = (
            encode_integer(request_id)
            + encode_integer(0)
            + encode_integer(bulk_repetitions)
            + _tlv(0x30, varbinds)
        )
        return _tlv(_GETBULK_REQUEST, body)

    body = (
        encode_integer(request_id)
        + encode_integer(0)  # error-status
        + encode_integer(0)  # error-index
        + _tlv(0x30, varbinds)
    )
    return _tlv(_GETNEXT_REQUEST if next_request else _GET_REQUEST, body)


def encode_get_request(
    request_id: int,
    oids: Sequence[str],
    *,
    next_request: bool = False,
    bulk_repetitions: int = 0,
) -> bytes:
    """A full SNMP message with an empty community, for tests of the PDU shape."""
    return _tlv(
        0x30,
        encode_integer(1)
        + encode_octet_string("")
        + _encode_pdu(
            request_id,
            oids,
            next_request=next_request,
            bulk_repetitions=bulk_repetitions,
        ),
    )


def build_message(
    oids: Sequence[str],
    community: str,
    *,
    next_request: bool = False,
    bulk_repetitions: int = 0,
) -> Tuple[bytes, int]:
    """Wire bytes plus the request id the reply must carry."""
    request_id = random.randint(1, 0x7FFFFFFF)
    message = _tlv(
        0x30,
        encode_integer(1)  # version 1 == SNMPv2c
        + encode_octet_string(community)
        + _encode_pdu(
            request_id,
            oids,
            next_request=next_request,
            bulk_repetitions=bulk_repetitions,
        ),
    )
    return message, request_id


# --------------------------------------------------------------------------
# BER decoding
# --------------------------------------------------------------------------


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise SnmpError("Truncated BER value")
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or offset + 2 + count > len(data):
            raise SnmpError("Truncated BER length")
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        start = offset + 2 + count
    else:
        length = length_byte
        start = offset + 2
    end = start + length
    if end > len(data):
        raise SnmpError("BER value runs past the end of the packet")
    return tag, data[start:end], end


def decode_oid(payload: bytes) -> str:
    if not payload:
        raise SnmpError("Empty OID")
    arcs = [str(payload[0] // 40), str(payload[0] % 40)]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(value))
            value = 0
    if value:
        raise SnmpError("Truncated OID")
    return ".".join(arcs)


def decode_value(tag: int, payload: bytes) -> Any:
    """Turn a BER payload into the Python value the caller cares about."""
    if tag == _TAG_INTEGER:
        return int.from_bytes(payload, "big", signed=True)
    if tag in (_TAG_COUNTER32, _TAG_GAUGE32, _TAG_TIMETICKS, _TAG_COUNTER64):
        return int.from_bytes(payload, "big", signed=False)
    if tag == _TAG_OID:
        return decode_oid(payload)
    if tag == _TAG_IP_ADDRESS:
        return ".".join(str(b) for b in payload)
    if tag == _TAG_NULL:
        return None
    if tag in (_TAG_OCTET_STRING, _TAG_OPAQUE):
        # Left as raw bytes: IP-MIB carries both MACs and addresses here, and
        # guessing a dotted-quad from any 4 bytes would invent addresses.
        # Callers use :func:`mac_to_str` / :func:`to_ip` to interpret them.
        return payload
    raise SnmpError(f"Unsupported SNMP value tag 0x{tag:02x}")


def parse_response(data: bytes) -> Tuple[int, List[Tuple[str, Any]]]:
    """Return ``(request_id, [(oid, value), ...])`` from a GetResponse."""
    tag, message, _ = _read_tlv(data, 0)
    if tag != 0x30:
        raise SnmpError(f"Expected a SEQUENCE, got tag 0x{tag:02x}")

    offset = 0
    _, version_bytes, offset = _read_tlv(message, offset)
    if int.from_bytes(version_bytes, "big", signed=True) not in (0, 1):
        raise SnmpError("Not an SNMPv1/v2c packet")
    _, _community, offset = _read_tlv(message, offset)
    pdu_tag, pdu, _ = _read_tlv(message, offset)
    if pdu_tag != _GET_RESPONSE:
        raise SnmpError(f"Expected a GetResponse, got tag 0x{pdu_tag:02x}")

    pdu_offset = 0
    _, rid_bytes, pdu_offset = _read_tlv(pdu, pdu_offset)
    request_id = int.from_bytes(rid_bytes, "big", signed=True)
    _, error_bytes, pdu_offset = _read_tlv(pdu, pdu_offset)
    _, index_bytes, pdu_offset = _read_tlv(pdu, pdu_offset)
    error_status = int.from_bytes(error_bytes, "big", signed=True)
    if error_status not in (0, 1):  # 0 = noError, 1 = tooBig (harmless for us)
        raise SnmpError(f"Agent returned error-status {error_status} at index "
                        f"{int.from_bytes(index_bytes, 'big', signed=True)}")

    _, varbind_bytes, _ = _read_tlv(pdu, pdu_offset)
    varbinds: List[Tuple[str, Any]] = []
    cursor = 0
    while cursor < len(varbind_bytes):
        _, entry, cursor = _read_tlv(varbind_bytes, cursor)
        entry_offset = 0
        oid_tag, oid_bytes, entry_offset = _read_tlv(entry, entry_offset)
        if oid_tag != _TAG_OID:
            raise SnmpError("Varbind without an OID")
        value_tag, value_bytes, _ = _read_tlv(entry, entry_offset)
        varbinds.append((decode_oid(oid_bytes), decode_value(value_tag, value_bytes)))
    return request_id, varbinds


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


def _explain(error: Optional[BaseException], host: str, port: int) -> str:
    """Turn a transport error into something an operator can act on."""
    text = str(error) if error else "no reply"
    lowered = text.lower()
    if isinstance(error, ConnectionResetError) or "forcibly closed" in lowered:
        return (
            f"SNMP {host}:{port} was refused (connection reset). The router is reachable but "
            "is not answering SNMP — check that SNMP is enabled and allowed through the firewall."
        )
    if isinstance(error, socket.timeout) or "no reply" in lowered or "timed out" in lowered:
        return (
            f"SNMP {host}:{port} did not answer within the timeout. Either SNMP is off, or the "
            "community string is not the one configured."
        )
    return f"SNMP {host}:{port} failed: {text}"


def _request(
    host: str,
    community: str,
    oids: Sequence[str],
    *,
    port: int,
    timeout: float,
    retries: int,
    next_request: bool,
    bulk_repetitions: int = 0,
) -> List[Tuple[str, Any]]:
    packet, request_id = build_message(
        oids,
        community,
        next_request=next_request,
        bulk_repetitions=bulk_repetitions,
    )
    last_error: Optional[BaseException] = None
    attempts = max(1, retries + 1)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for attempt in range(attempts):
            try:
                sock.sendto(packet, (host, port))
                deadline = time.monotonic() + timeout
                strays = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout(f"no reply from {host}:{port}")
                    ready, _, _ = select.select([sock], [], [], remaining)
                    if not ready:
                        raise socket.timeout(f"no reply from {host}:{port}")
                    data, _addr = sock.recvfrom(65535)
                    try:
                        rid, varbinds = parse_response(data)
                    except SnmpError:
                        # A trap or a malformed packet from something else on
                        # the segment; it is not our answer.
                        rid, varbinds = -1, []
                    if rid == request_id:
                        return varbinds
                    strays += 1
                    if strays > MAX_STRAY_PACKETS:
                        # A busy agent can drown the reply. Fail this attempt
                        # rather than sitting in the read loop.
                        raise SnmpError(
                            f"agent is answering other queries faster than ours ({strays} unrelated packets)"
                        )
            except (SnmpError, socket.timeout, OSError) as exc:
                last_error = exc
                # Slow or lossy links drop the first datagram: give the agent a
                # moment before the retry instead of firing again immediately.
                if attempt + 1 < attempts:
                    time.sleep(0.15 * (attempt + 1))

    raise SnmpError(_explain(last_error, host, port))


def get(
    host: str,
    oids: Sequence[str],
    *,
    community: str = "public",
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> List[Tuple[str, Any]]:
    """GET a fixed list of OIDs."""
    return _request(
        host, community, oids, port=port, timeout=timeout, retries=retries, next_request=False
    )


def _arcs(oid: str) -> Tuple[int, ...]:
    try:
        return tuple(int(part) for part in oid.strip().strip(".").split("."))
    except ValueError as exc:  # malformed OID from a broken agent
        raise SnmpError(f"Agent returned a malformed OID {oid!r}") from exc


def walk(
    host: str,
    oid: str,
    *,
    community: str = "public",
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_entries: int = MAX_WALK_ENTRIES,
    bulk_repetitions: int = DEFAULT_BULK_REPETITIONS,
) -> List[Tuple[str, Any]]:
    """Walk *oid*'s subtree, using GETBULK where the agent allows it.

    Returns ``[(oid, value), ...]`` in lexical order. It raises
    :class:`SnmpError` when the agent cannot be talked to at all, so an empty
    list always means "the agent answered and the table is empty" — the
    difference the verification path has to report honestly.

    GETBULK fetches many rows per round trip (the difference between one packet
    and forty on a slow router). Agents that reject it — SNMPv1, or an
    implementation that answers ``tooBig`` — are walked one row at a time
    instead, and the repetition count halves on every ``tooBig`` so a router
    with a small MTU still makes progress.
    """
    prefix = _arcs(oid)
    results: List[Tuple[str, Any]] = []
    current = oid
    repetitions = max(0, bulk_repetitions)

    while len(results) < max_entries:
        try:
            varbinds = _request(
                host,
                community,
                [current],
                port=port,
                timeout=timeout,
                retries=retries,
                next_request=True,
                bulk_repetitions=repetitions,
            )
        except SnmpError:
            if repetitions == 0 or results:
                raise
            # First request failed with GETBULK: fall back for the whole walk.
            repetitions = 0
            continue

        if not varbinds:
            if repetitions > MIN_BULK_REPETITIONS:
                # "tooBig" arrives as an empty varbind list: ask for less.
                repetitions = max(MIN_BULK_REPETITIONS, repetitions // 2)
                continue
            break

        advanced = False
        for next_oid, value in varbinds:
            next_arcs = _arcs(next_oid)
            if next_arcs[: len(prefix)] != prefix or next_arcs <= _arcs(current):
                # Left the subtree: the walk is done, including the rest of a
                # bulk answer that ran past the end of the table.
                return results
            results.append((next_oid, value))
            current = next_oid
            advanced = True
            if len(results) >= max_entries:
                break

        if not advanced:
            break

    return results


# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------


def mac_to_str(value: Any) -> Optional[str]:
    """Convert an SNMP MAC value into the inventory's 12-hex-digit form.

    Device rows store MACs as 12 uppercase hex digits with no separators, so
    that is what this produces. Unknown or implausible values return ``None``
    rather than a plausible-looking fiction.
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        cleaned = value.replace(":", "").replace("-", "").replace(".", "").strip()
        if len(cleaned) != 12 or any(c not in "0123456789abcdefABCDEF" for c in cleaned):
            return None
        raw = bytes.fromhex(cleaned)
    else:
        return None
    if len(raw) != 6:
        return None
    if raw in (b"\x00\x00\x00\x00\x00\x00", b"\xff\xff\xff\xff\xff\xff"):
        return None
    return raw.hex().upper()


def to_ip(value: Any) -> Optional[str]:
    """Normalise whatever IP-MIB handed back into a dotted-quad string."""
    if isinstance(value, str) and value.count(".") == 3:
        try:
            octets = [int(part) for part in value.split(".")]
        except ValueError:
            return None
        if len(octets) == 4 and all(0 <= octet <= 255 for octet in octets):
            return ".".join(str(octet) for octet in octets)
        return None
    if isinstance(value, (bytes, bytearray)) and len(value) == 4:
        return ".".join(str(b) for b in value)
    return None
