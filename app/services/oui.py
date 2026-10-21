"""MAC OUI (vendor prefix) resolution.

Deliberately dependency-free — stdlib only — so it can be imported by the
async discovery service, by the (sync) ARP discovery path, and by the unit
test suite without pulling in scapy, nmap, or SQLAlchemy.

The table is a trimmed set of the OUIs that actually show up on a home or
small-office network. Extend as needed; a full IEEE registry would be a
database import, not a source file.
"""
from __future__ import annotations

from typing import Dict, Optional

# First three octets, uppercase, no separators. Merged from the previous
# inline tables in app/services/recon.py and frontend/src/utils/oui.ts so the
# backend and the UI now agree on vendor names.
OUI_VENDORS: Dict[str, str] = {
    # Virtualisation
    "000569": "VMware",
    "000C29": "VMware",
    "001C14": "VMware",
    "005056": "VMware",
    # Apple
    "000393": "Apple",
    "000A27": "Apple",
    "000D93": "Apple",
    "0010FA": "Apple",
    "001451": "Apple",
    "0016CB": "Apple",
    "0017F2": "Apple",
    "0019E3": "Apple",
    "0026BB": "Apple",
    "3C0754": "Apple",
    "A45E60": "Apple",
    "B8E856": "Apple",
    "F0DCE2": "Apple",
    # Cisco
    "00000C": "Cisco",
    "0001C7": "Cisco",
    "0002FC": "Cisco",
    "0003E3": "Cisco",
    "001A2B": "Cisco Systems",
    "0050C2": "Cisco Systems",
    "5C5015": "Cisco Systems",
    "00059A": "Cisco-Linksys",
    "001315": "Cisco-Linksys",
    # Intel
    "001302": "Intel",
    "0018DE": "Intel",
    "001B21": "Intel",
    "001CBF": "Intel",
    "F875A4": "Intel",
    "3413E8": "Intel",
    "4C1D96": "Intel",
    "7C5CF8": "Intel",
    # Samsung
    "0007AB": "Samsung",
    "001247": "Samsung",
    "001C7B": "Samsung",
    "0021D2": "Samsung",
    # Microsoft
    "0003FF": "Microsoft",
    "000D3A": "Microsoft",
    "00155D": "Microsoft",
    "28184D": "Microsoft",
    "DC4A9E": "Microsoft",
    # HP / HPE
    "0001E6": "HP",
    "000854": "HP",
    "000F20": "HP",
    "2C6BF5": "HP Enterprise",
    "3C4A92": "HP Enterprise",
    "001708": "HP Inc",
    # Dell
    "00065B": "Dell",
    "000874": "Dell",
    "000F1F": "Dell",
    "0021B7": "Dell",
    "E0D55E": "Dell",
    "F0761C": "Dell",
    # Single-board / embedded
    "B827EB": "Raspberry Pi",
    "3A8024": "Raspberry Pi",
    "D83ADD": "Raspberry Pi",
    # Network gear
    "001E06": "Juniper Networks",
    "0019E2": "Juniper Networks",
    "BC9FEF": "Ubiquiti",
    "DC9FDB": "Ubiquiti",
    "E063DA": "Ubiquiti",
    "246895": "Fortinet",
    "0009BF": "Fortinet",
    # Misc
    "70B3D5": "IEEE Registration Authority",
    "000000": "Xerox",
    "ACDE48": "Private",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Return *mac* as 12 uppercase hex characters, or None if unusable.

    Accepts colon-, dash-, and dot-separated forms as well as bare hex.
    """
    if not mac:
        return None
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").strip().upper()
    if len(cleaned) != 12:
        return None
    if any(ch not in "0123456789ABCDEF" for ch in cleaned):
        return None
    return cleaned


def oui_prefix(mac: Optional[str]) -> Optional[str]:
    """Return the 6-character OUI prefix of *mac*, or None if unusable."""
    normalized = normalize_mac(mac)
    return normalized[:6] if normalized else None


def is_locally_administered(mac: Optional[str]) -> bool:
    """True when *mac* has the locally-administered bit set (RFC 1122).

    The second-least-significant bit of the first octet is the "locally
    administered" flag. Consumer OSes (Android, iOS, Windows 10+, macOS)
    randomize the MAC on every network join for privacy, which sets this bit.
    A randomised MAC means the OUI is not a real vendor prefix, so vendor and
    OS lookups against it are meaningless — callers should say so rather than
    present a confident wrong answer.
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    try:
        first_octet = int(normalized[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0b00000010)


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Resolve a vendor name from a MAC address, or None when unknown.

    Returns None for locally-administered (randomised) MACs, whose OUI is not a
    real vendor prefix — reporting a vendor there would be a guess dressed as
    fact.
    """
    if is_locally_administered(mac):
        return None
    prefix = oui_prefix(mac)
    return OUI_VENDORS.get(prefix) if prefix else None
