"""Version-based CVE matching against a bundled, refreshable catalogue.

The NSE path answers "is this service vulnerable" only for the scripts this
install happens to have. That leaves a real gap: Apache 2.4.49 with a path
traversal is a *version* fact, and knowing it needs no script at all — nmap
already reported the version during the deep scan.

This module closes that gap without pretending to be NVD. A bundled catalogue of
affected version ranges is matched against the product and version strings nmap
returned, and matches flow into the same ``vulnerabilities`` table the NSE
findings use. It is deliberately a *seed* catalogue: the loader is the stable
interface, and ``refresh_from_nvd`` is how it grows.

Two honest limits are encoded in the output rather than hidden:

* A distro backport (``1.0.1-ubuntu0.2``) is newer than it looks. Version
  ranges cannot see that, so findings say so and stay advisory.
* A range match is not a proof of exploitability; it is a reason to look.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

logger = logging.getLogger("netpulse.cve_feed")

CATALOG_PATH = Path(__file__).with_name("cve_catalog.json")

# Leading version only: "2.4.49 (Ubuntu)" and "1.0.1-ubuntu0.2" both reduce to
# their numeric core, because what follows a dash is a packager's revision, not
# upstream's version.
_VERSION_HEAD = re.compile(r"^\s*v?(\d+(?:\.\d+)*)(?:([a-z])(\d+)?)?", re.IGNORECASE)


@dataclass(slots=True)
class CveMatch:
    """One catalogue advisory that applies to a detected service."""

    cve_id: str
    summary: str
    severity: str
    port: int | None
    protocol: str | None
    product: str
    version: str
    reference: str | None = None

    @property
    def title(self) -> str:
        return f"{self.cve_id}: {self.summary}"

    @property
    def detail(self) -> str:
        location = f"{self.product} {self.version}".strip()
        where = f" on port {self.port}/{self.protocol}" if self.port else ""
        reference = f" {self.reference}" if self.reference else ""
        return (
            f"{location}{where} is inside the affected range for {self.cve_id}. "
            "Version-based match: a vendor backport may already be patched — "
            f"confirm against the advisory.{reference}"
        )


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Reduce a banner version to comparable numbers.

    ``"2.4.49"`` -> ``(2, 4, 49)``; ``"7.1p2"`` -> ``(7, 1, 2)`` (the ``p`` patch
    level is what makes OpenSSH 7.1p2 fixed while 7.1p1 is not); ``"1.0.1g"`` ->
    ``(1, 0, 1, 7)`` so the letter revision sorts after ``f``.
    """
    match = _VERSION_HEAD.match(str(text or ""))
    if not match:
        return None
    parts: list[int] = [int(piece) for piece in match.group(1).split(".") if piece.isdigit()]
    letter, digits = match.group(2), match.group(3)
    if letter and digits:
        parts.append(int(digits))
    elif letter:
        parts.append(ord(letter.lower()) - 96)
    return tuple(parts) if parts else None


def _compare(left: Sequence[int], right: Sequence[int]) -> int:
    """Compare version tuples, treating a missing element as zero.

    ``(2, 4)`` and ``(2, 4, 0)`` are the same version; without this, padded
    ranges would report every unpadded banner as older than it is.
    """
    width = max(len(left), len(right))
    for index in range(width):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        if a != b:
            return -1 if a < b else 1
    return 0


def version_in_range(version: tuple[int, ...] | None, entry: Mapping[str, Any]) -> bool:
    """Whether *version* falls inside one catalogue range entry.

    A range with no ``introduced`` starts at the beginning of the product; one
    with no ``fixed`` is still unpatched upstream.
    """
    if version is None:
        return False
    introduced = parse_version(entry.get("introduced"))
    fixed = parse_version(entry.get("fixed"))
    if introduced is not None and _compare(version, introduced) < 0:
        return False
    if fixed is not None and _compare(version, fixed) >= 0:
        return False
    return True


def _field(entry: Any, name: str) -> Any:
    """Read *name* from a dict or an object (PortObservation and friends)."""
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _product_haystack(entry: Any) -> str:
    product = _field(entry, "product") or ""
    service = _field(entry, "service") or ""
    return f"{product} {service}".strip().lower()


@lru_cache(maxsize=1)
def load_catalog(path: Path | None = None) -> tuple[dict[str, Any], ...]:
    """Read the bundled catalogue once per process.

    A missing or malformed file yields an empty catalogue rather than an
    exception: a broken feed must not take the scan down with it.
    """
    target = path or CATALOG_PATH
    try:
        raw = json.loads(Path(target).read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("CVE catalogue missing at %s; version matching is off.", target)
        return ()
    except Exception as exc:  # noqa: BLE001 - bad feed is a warning, not a crash
        logger.warning("Could not read CVE catalogue %s: %s", target, exc)
        return ()

    advisories = raw.get("advisories") if isinstance(raw, dict) else raw
    if not isinstance(advisories, list):
        return ()
    return tuple(entry for entry in advisories if isinstance(entry, dict) and entry.get("cve_id"))


def catalogue_updated() -> str | None:
    try:
        raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - informational only
        return None
    return raw.get("updated") if isinstance(raw, dict) else None


def find_cve_matches(
    ports: Iterable[Any],
    catalog: Sequence[Mapping[str, Any]] | None = None,
) -> list[CveMatch]:
    """Match detected service versions against the catalogue.

    Takes the observations from a deep scan (objects or plain dicts), so the
    matching rules are testable without nmap.
    """
    advisories = catalog if catalog is not None else load_catalog()
    matches: list[CveMatch] = []
    seen: set[tuple[str, int | None, str | None]] = set()

    for entry in ports or []:
        haystack = _product_haystack(entry)
        if not haystack:
            continue
        version_text = str(_field(entry, "version") or "").strip()
        version = parse_version(version_text)
        if version is None:
            continue
        port = _field(entry, "port")
        protocol = _field(entry, "protocol")
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None

        for advisory in advisories:
            terms = advisory.get("products") or []
            if not any(str(term).lower() in haystack for term in terms):
                continue
            ranges = advisory.get("ranges") or []
            if not any(version_in_range(version, item) for item in ranges if isinstance(item, dict)):
                continue

            cve_id = str(advisory["cve_id"]).upper()
            key = (cve_id, port, str(protocol) if protocol else None)
            if key in seen:
                continue
            seen.add(key)

            matches.append(
                CveMatch(
                    cve_id=cve_id,
                    summary=str(advisory.get("summary") or "known vulnerability"),
                    severity=str(advisory.get("severity") or "medium").lower(),
                    port=port,
                    protocol=str(protocol) if protocol else None,
                    product=str(_field(entry, "product") or _field(entry, "service") or "").strip(),
                    version=version_text,
                    reference=advisory.get("reference"),
                )
            )

    matches.sort(key=lambda item: (item.port or 0, item.cve_id))
    return matches


def refresh_from_nvd(api_key: str | None = None) -> int:  # pragma: no cover - network
    """Fetch recent CVE records from NVD and print the entries it can map.

    Kept out of the request path on purpose: a console that scans a LAN must not
    depend on an internet lookup to answer. Run it deliberately, review the
    output, and commit the entries worth keeping — the catalogue is version
    ranges, and those need a human to decide the product mapping.
    """
    import httpx

    headers = {"apiKey": api_key} if api_key else {}
    with httpx.Client(timeout=30.0) as client:
        response = client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 20},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()

    found = 0
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = next(
            (
                entry.get("value", "")
                for entry in cve.get("descriptions", [])
                if entry.get("lang") == "en"
            ),
            "",
        )
        print(json.dumps({"cve_id": cve_id, "summary": description[:200]}, ensure_ascii=False))
        found += 1
    return found
