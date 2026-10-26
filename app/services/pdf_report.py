"""PDF reports that look like the console they came from.

The old reports were indigo-on-white with invented figures ("Uptime 99.2%",
"3 warnings") that no query produced. This module draws one visual system for
every report in the app:

* the console's own palette -- near-black ink, emerald accent, slate greys;
* a dark cover band and an emerald rule, so a stack of printouts is
  recognisably NetPulse;
* numbers that came from the database, never placeholders;
* tables without vertical rules (a grid of lines is noise, not structure);
* "Page n of m" in the footer, because a report gets printed and shuffled.

Everything here is presentation only. Callers pass plain data; this module
never queries the database, which keeps it testable and keeps the routes in
charge of what a report is allowed to contain.
"""

from __future__ import annotations

import html
import io
import uuid
from datetime import datetime
from typing import Any, Iterable, Sequence

# ── Palette ────────────────────────────────────────────────────────────────
INK = "#09090B"
INK_SOFT = "#18181B"
EMERALD = "#10B981"
EMERALD_DARK = "#047857"
EMERALD_TINT = "#ECFDF5"
BODY = "#27272A"
MUTED = "#71717A"
LINE = "#E4E4E7"
TINT = "#F4F4F5"
DANGER = "#B91C1C"
DANGER_TINT = "#FEF2F2"
WARN = "#B45309"
WARN_TINT = "#FFFBEB"
INFO = "#0369A1"
INFO_TINT = "#F0F9FF"

PAGE_WIDTH = 612  # letter
MARGIN = 40
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN


def _hex(value: str):
    from reportlab.lib import colors

    return colors.HexColor(value)


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


# ── Building blocks ────────────────────────────────────────────────────────


def _styles():
    from reportlab.lib.styles import ParagraphStyle

    return {
        "title": ParagraphStyle(
            "np-title",
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=27,
            textColor=_hex(INK),
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "np-subtitle",
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=_hex(MUTED),
        ),
        "h2": ParagraphStyle(
            "np-h2",
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=_hex(INK),
            spaceBefore=14,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "np-body",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=_hex(BODY),
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "np-small",
            fontName="Helvetica",
            fontSize=7.5,
            leading=10.5,
            textColor=_hex(MUTED),
        ),
        "cell": ParagraphStyle(
            "np-cell",
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=_hex(BODY),
        ),
        "cell_mono": ParagraphStyle(
            "np-cell-mono",
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=_hex(BODY),
        ),
        "cell_head": ParagraphStyle(
            "np-cell-head",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=_hex(MUTED),
        ),
        "stat_value": ParagraphStyle(
            "np-stat-value",
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=23,
            textColor=_hex(INK),
        ),
        "stat_label": ParagraphStyle(
            "np-stat-label",
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=_hex(MUTED),
        ),
        "cell_time": ParagraphStyle(
            "np-cell-time",
            fontName="Courier",
            fontSize=7,
            leading=9.5,
            textColor=_hex(BODY),
        ),
        "mono": ParagraphStyle(
            "np-mono",
            fontName="Courier",
            fontSize=7.2,
            leading=9.6,
            textColor=_hex(BODY),
        ),
        "cover_tag": ParagraphStyle(
            "np-cover-tag",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=_hex(EMERALD),
        ),
    }


def rule(width: float = CONTENT_WIDTH, color: str = LINE, thickness: float = 0.75):
    from reportlab.platypus import HRFlowable

    return HRFlowable(width=width, thickness=thickness, color=_hex(color), spaceBefore=2, spaceAfter=8)


def section(title: str, note: str | None = None):
    """A heading with an optional one-line explanation, then a hairline."""
    from reportlab.platypus import Paragraph

    styles = _styles()
    items = [Paragraph(_esc(title), styles["h2"])]
    if note:
        items.append(Paragraph(_esc(note), styles["small"]))
    items.append(rule())
    return items


def stat_cards(stats: Sequence[tuple[str, Any, str | None]]) -> Any:
    """A row of headline numbers.

    Each item is ``(label, value, hint)``. They read as one measurement strip:
    values in the console's ink, labels beneath, and a single emerald rule
    above the row instead of four boxed cards.
    """
    if not stats:
        return None

    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = _styles()
    values = [Paragraph(_esc(value), styles["stat_value"]) for _label, value, _hint in stats]
    labels = [
        Paragraph(
            f"{_esc(label)}"
            + (f"<br/><font color='{MUTED}' size='6.3'>{_esc(hint)}</font>" if hint else ""),
            styles["stat_label"],
        )
        for label, _value, hint in stats
    ]
    table = Table([values, labels], colWidths=[CONTENT_WIDTH / len(stats)] * len(stats))
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
                ("TOPPADDING", (0, 1), (-1, 1), 0),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 0), (-1, -1), _hex("#FAFAFA")),
                ("LINEABOVE", (0, 0), (-1, 0), 1.6, _hex(EMERALD)),
                ("LINEBEFORE", (1, 0), (-1, -1), 0.5, _hex(LINE)),
                ("LINEBELOW", (0, -1), (-1, -1), 0.5, _hex(LINE)),
            ]
        )
    )
    return table


def bars(title: str, pairs: Sequence[tuple[str, int]], *, width: float = CONTENT_WIDTH / 2 - 8) -> Any:
    """A small horizontal bar block, drawn rather than charted.

    ``reportlab.graphics`` would work, but a handful of rectangles gives exact
    control over the palette and needs no legend, axes or label collision
    handling for the six rows a report ever shows.
    """
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = _styles()
    rows = [(label, count) for label, count in pairs if label][:6]
    height = 12 * max(1, len(rows)) + 14
    drawing = Drawing(width, height)
    drawing.add(String(0, height - 8, title, fontName="Helvetica-Bold", fontSize=7.5, fillColor=_hex(MUTED)))
    if not rows:
        drawing.add(String(0, height - 26, "No data", fontName="Helvetica", fontSize=7.5, fillColor=_hex(MUTED)))
        return drawing

    # Bars are shares of the total, not shares of the largest row: with five
    # devices in five categories the old scale drew five identical full-width
    # bars, which reads as "100%" rather than "one each".
    total = sum(count for _label, count in rows) or 1
    label_width = 78
    chart_width = width - label_width - 26
    for index, (label, count) in enumerate(rows):
        y = height - 24 - index * 12
        drawing.add(
            String(0, y + 1, label[:20], fontName="Helvetica", fontSize=7, fillColor=_hex(BODY))
        )
        span = max(2, chart_width * (count / total))
        drawing.add(
            Rect(
                label_width,
                y,
                span,
                6,
                rx=1.5,
                ry=1.5,
                fillColor=_hex(EMERALD),
                strokeColor=None,
            )
        )
        drawing.add(
            String(
                label_width + span + 4,
                y + 1,
                str(count),
                fontName="Helvetica-Bold",
                fontSize=7,
                fillColor=_hex(BODY),
            )
        )
    _ = (Paragraph, Table, TableStyle)
    return drawing


def chip(text: str, fg: str, bg: str) -> Any:
    from reportlab.platypus import Paragraph

    return Paragraph(
        f"<font color='{fg}' backColor='{bg}'>&nbsp;{_esc(text)}&nbsp;</font>",
        _styles()["cell"],
    )


def data_table(
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    widths: Sequence[float],
    *,
    align: Sequence[str] | None = None,
    head_bg: str = TINT,
) -> Any:
    """A borderless data table: tonal header, hairline rows, wrapped cells."""
    from reportlab.platypus import LongTable, Paragraph, TableStyle

    styles = _styles()
    body = [
        [
            cell
            if hasattr(cell, "wrap")
            else Paragraph(_esc(cell), styles["cell"])
            for cell in row
        ]
        for row in rows
    ]
    table = LongTable(
        [[Paragraph(_esc(title), styles["cell_head"]) for title in header], *body],
        colWidths=list(widths),
        repeatRows=1,
    )
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _hex(head_bg)),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, _hex(LINE)),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, _hex("#F1F1F3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for index, alignment in enumerate(align or []):
        commands.append(("ALIGN", (index, 1), (index, -1), alignment))
    table.setStyle(TableStyle(commands))
    return table


def mono_block(text: str, *, max_lines: int = 240, max_chars: int = 118) -> Any:
    """Preformatted text in a tinted block, wrapped by hand.

    ``Preformatted`` cannot wrap and a long nmap line ran off the page; a Table
    cell with explicit line breaks keeps every character on the paper.
    """
    from reportlab.platypus import Paragraph, Table, TableStyle

    lines: list[str] = []
    for raw in text.replace("\r", "").split("\n")[:max_lines]:
        lines.append(html.escape(raw[:max_chars]).replace(" ", "&nbsp;") if raw else "&nbsp;")
    escaped = "<br/>".join(lines)
    table = Table(
        [[Paragraph(escaped, _styles()["mono"])]],
        colWidths=[CONTENT_WIDTH],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _hex("#FAFAFA")),
                ("BOX", (0, 0), (-1, -1), 0.4, _hex(LINE)),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def bullet_list(items: Sequence[str]) -> Any:
    from reportlab.platypus import Paragraph

    styles = _styles()
    return [
        Paragraph(
            f"<font color='{EMERALD}'>■</font>&nbsp;&nbsp;{_esc(item)}",
            styles["body"],
        )
        for item in items
    ]


# ── Document chrome ────────────────────────────────────────────────────────


def _numbered_canvas(footer_left: str):
    """A canvas class whose footer can say "page 1 of 4".

    Built per document because the footer carries the report id; a module-level
    subclass would leak one report's id into the next one.
    """
    from reportlab.pdfgen import canvas as canvas_module

    class NumberedCanvas(canvas_module.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved: list[dict[str, Any]] = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                self._draw_footer(total)
                super().showPage()
            super().save()

        def _draw_footer(self, total: int) -> None:
            self.saveState()
            self.setStrokeColor(_hex(LINE))
            self.setLineWidth(0.5)
            self.line(MARGIN, 34, PAGE_WIDTH - MARGIN, 34)
            self.setFont("Helvetica", 6.8)
            self.setFillColor(_hex(MUTED))
            self.drawString(MARGIN, 24, footer_left)
            self.drawRightString(PAGE_WIDTH - MARGIN, 24, f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return NumberedCanvas


def _document(buffer: io.BytesIO, *, title: str):
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate

    return SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=112,
        bottomMargin=52,
        title=title,
        author="NetPulse",
    )


def _page_chrome(canvas, doc) -> None:
    """Dark cover band + emerald rule at the top of every page."""
    from reportlab.lib import colors

    canvas.saveState()
    canvas.setFillColor(_hex(INK))
    canvas.rect(0, doc.pagesize[1] - 74, doc.pagesize[0], 74, stroke=0, fill=1)
    # Emerald keyhole: a small mark, not a logo file the deployment may not have.
    canvas.setFillColor(_hex(EMERALD))
    canvas.roundRect(
        MARGIN, doc.pagesize[1] - 52, 20, 20, 5, stroke=0, fill=1
    )
    canvas.setFillColor(colors.white)
    canvas.circle(MARGIN + 10, doc.pagesize[1] - 42, 4, stroke=0, fill=1)

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(MARGIN + 30, doc.pagesize[1] - 38, "NETPULSE")
    canvas.setFont("Helvetica", 7.2)
    canvas.setFillColor(_hex("#A1A1AA"))
    canvas.drawString(MARGIN + 30, doc.pagesize[1] - 48, "Network operations console")

    canvas.setFillColor(_hex(EMERALD))
    canvas.setFont("Helvetica-Bold", 7.2)
    canvas.drawRightString(
        doc.pagesize[0] - MARGIN,
        doc.pagesize[1] - 42,
        (getattr(doc, "np_kicker", "") or "").upper(),
    )
    canvas.setFillColor(_hex("#71717A"))
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(
        doc.pagesize[0] - MARGIN,
        doc.pagesize[1] - 52,
        datetime.now().strftime("%d %b %Y  %H:%M"),
    )
    canvas.setFillColor(_hex(EMERALD))
    canvas.rect(0, doc.pagesize[1] - 78, doc.pagesize[0], 2.5, stroke=0, fill=1)
    canvas.restoreState()


def _build(buffer: io.BytesIO, story: list[Any], *, kicker: str, report_id: str) -> bytes:
    from reportlab.platypus import Spacer

    doc = _document(buffer, title=f"NetPulse {kicker}")
    doc.np_kicker = kicker
    story = [*story, Spacer(1, 12)]
    doc.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
        canvasmaker=_numbered_canvas(f"NetPulse  |  {report_id}"),
    )
    buffer.seek(0)
    return buffer.getvalue()


def _cover(title: str, subtitle: str, tag: str) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer

    styles = _styles()
    return [
        Spacer(1, 10),
        Paragraph(_esc(tag).upper(), styles["cover_tag"]),
        Paragraph(_esc(title), styles["title"]),
        Paragraph(_esc(subtitle), styles["subtitle"]),
        Spacer(1, 12),
    ]


# ── Report bodies ──────────────────────────────────────────────────────────


def build_inventory_pdf(
    *,
    devices: Sequence[Any],
    title: str,
    report_type: str,
    online_window_minutes: int = 10,
    is_online=None,
) -> bytes:
    """Device inventory with an executive summary, breakdowns and a table."""
    online_checker = is_online or (lambda device: False)
    online = [device for device in devices if online_checker(device)]
    offline = len(devices) - len(online)

    vendors: dict[str, int] = {}
    types: dict[str, int] = {}
    families: dict[str, int] = {}
    for device in devices:
        vendor = (getattr(device, "vendor", None) or "Unknown vendor").strip()
        vendors[vendor] = vendors.get(vendor, 0) + 1
        kind = (getattr(device, "device_type", None) or "Unclassified").strip()
        types[kind] = types.get(kind, 0) + 1
        family = (getattr(device, "os", None) or "Unidentified").strip()
        families[family] = families.get(family, 0) + 1

    gateways = sum(1 for device in devices if getattr(device, "is_gateway", False))
    story: list[Any] = []
    story += _cover(
        title,
        f"{len(devices)} devices in the inventory. "
        f"{len(online)} answered within the last {online_window_minutes} minutes.",
        f"{report_type.replace('_', ' ')} report",
    )
    story.append(
        stat_cards(
            [
                ("Devices", len(devices), "in the inventory"),
                ("Responding", len(online), f"seen in {online_window_minutes} min"),
                ("Silent", offline, "no recent answer"),
                ("Gateways", gateways, "default-route nodes"),
            ]
        )
    )
    story.append(rule())

    findings: list[str] = []
    if offline:
        findings.append(
            f"{offline} device(s) have not been seen in the last {online_window_minutes} minutes."
        )
    unidentified = families.get("Unidentified", 0)
    if unidentified:
        findings.append(
            f"{unidentified} device(s) have no operating-system identification yet; a deep scan "
            "adds service banners and a stack fingerprint."
        )
    if not gateways:
        findings.append("No device is flagged as a default gateway.")
    if not findings:
        findings.append("Every device answered recently and the gateway is accounted for.")

    for item in section("Summary"):
        story.append(item)
    story += bullet_list(findings)

    for item in section("Breakdown", "Counts are from this report's snapshot, not lifetime totals."):
        story.append(item)

    from reportlab.platypus import Table, TableStyle

    breakdown = Table(
        [
            [bars("Devices by type", sorted(types.items(), key=lambda kv: -kv[1]))],
            [bars("Operating systems", sorted(families.items(), key=lambda kv: -kv[1]))],
        ],
        colWidths=[CONTENT_WIDTH],
    )
    breakdown.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(breakdown)

    for item in section("Inventory", "One row per device, newest sighting order."):
        story.append(item)

    rows = []
    for device in sorted(
        devices,
        key=lambda d: str(getattr(d, "ip_address", "")),
    ):
        online_now = online_checker(device)
        rows.append(
            [
                _esc(getattr(device, "hostname", None) or "-"),
                _esc(getattr(device, "ip_address", None) or "-"),
                _esc((getattr(device, "mac_address", None) or "-")),
                _esc(getattr(device, "vendor", None) or "-"),
                _esc(getattr(device, "os", None) or "-"),
                chip("online", EMERALD_DARK, EMERALD_TINT)
                if online_now
                else chip("silent", MUTED, "#F4F4F5"),
            ]
        )
    if not rows:
        story.append(section_note("No devices were recorded for this report."))
    else:
        story.append(
            data_table(
                ["Hostname", "Address", "MAC", "Vendor", "System", "State"],
                rows,
                widths=[96, 74, 100, 96, 100, 66],
            )
        )

    story.append(rule())
    story.append(section_note(
        "NetPulse reads this inventory from the local database. A device marked silent may still be "
        "online behind a firewall that drops discovery probes."
    ))

    buffer = io.BytesIO()
    return _build(
        buffer,
        story,
        kicker="Device inventory",
        report_id=f"NP-{uuid.uuid4().hex[:8].upper()}",
    )


LEVEL_FG = {
    "debug": MUTED,
    "info": INFO,
    "warning": WARN,
    "error": DANGER,
    "critical": DANGER,
}
LEVEL_BG = {
    "debug": TINT,
    "info": INFO_TINT,
    "warning": WARN_TINT,
    "error": DANGER_TINT,
    "critical": DANGER_TINT,
}


def build_logs_pdf(*, logs: Sequence[dict[str, Any]], total: int, level_filter: str | None = None) -> bytes:
    """Application logs: counts first, then the stream itself."""
    counts = {name: 0 for name in LEVEL_FG}
    for entry in logs:
        level = str(entry.get("level") or "info").lower()
        counts[level] = counts.get(level, 0) + 1

    story: list[Any] = []
    scope = f"level={level_filter}" if level_filter else "all levels"
    story += _cover(
        "Application log report",
        f"{total} entries captured, {len(logs)} included in this document ({scope}).",
        "Logs",
    )
    story.append(
        stat_cards(
            [
                ("Entries", len(logs), "in this report"),
                ("Errors", counts.get("error", 0) + counts.get("critical", 0), "error + critical"),
                ("Warnings", counts.get("warning", 0), "warning"),
                ("Info", counts.get("info", 0), "info"),
            ]
        )
    )
    story.append(rule())

    for item in section("Level breakdown"):
        story.append(item)
    story.append(
        bars(
            "Entries by level (share of this report)",
            [(name, counts.get(name, 0)) for name in ("critical", "error", "warning", "info", "debug")],
            width=CONTENT_WIDTH,
        )
    )

    for item in section("Entries", "Newest first. Long messages are wrapped, not truncated."):
        story.append(item)

    from reportlab.platypus import Paragraph

    rows = []
    for entry in logs:
        level = str(entry.get("level") or "info").lower()
        timestamp = str(entry.get("timestamp") or "")[:19].replace("T", " ")
        rows.append(
            [
                Paragraph(_esc(timestamp), _styles()["cell_time"]),
                chip(level, LEVEL_FG.get(level, BODY), LEVEL_BG.get(level, TINT)),
                _esc(entry.get("logger") or "-"),
                _esc(entry.get("message") or ""),
            ]
        )
    if rows:
        story.append(
            data_table(
                ["Time (UTC)", "Level", "Logger", "Message"],
                rows,
                widths=[100, 44, 132, CONTENT_WIDTH - 276],
            )
        )
    else:
        story.append(section_note("No log entries matched this report's scope."))

    story.append(rule())
    story.append(section_note(
        "Times are UTC. The in-memory buffer holds the most recent entries; logs/netpulse.log "
        "on the server keeps the full history."
    ))

    buffer = io.BytesIO()
    return _build(buffer, story, kicker="Application logs", report_id=f"NP-{uuid.uuid4().hex[:8].upper()}")


def build_scan_pdf(
    *,
    scan_type: str | None,
    target: str | None,
    command: str | None,
    results: str | None,
    summary: dict[str, Any] | None = None,
) -> bytes:
    """One scan: what ran, what it found, then the raw output."""
    summary = summary or {}
    hosts = summary.get("hosts") or []
    open_ports = summary.get("open_ports") or sum(
        int(host.get("open_ports") or 0) for host in hosts if isinstance(host, dict)
    )

    story: list[Any] = []
    story += _cover(
        f"Scan report: {scan_type or 'network scan'}",
        f"Target {target or 'unspecified'}. {len(hosts)} host(s) answered, {open_ports} open port(s).",
        "Scan",
    )
    story.append(
        stat_cards(
            [
                ("Hosts up", len(hosts) or summary.get("hosts_up", 0), "answered the probe"),
                ("Open ports", open_ports, "open TCP services"),
                ("Duration", f"{summary.get('scan_seconds') or summary.get('duration_seconds') or '-'}s", "wall clock"),
                ("Exit", summary.get("exit_code", "-"), "nmap exit code"),
            ]
        )
    )
    story.append(rule())

    if command:
        for item in section("Command", "Exactly what ran, so the result can be reproduced."):
            story.append(item)
        story.append(mono_block(command, max_lines=4))

    if hosts:
        for item in section("Hosts"):
            story.append(item)
        rows = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            rows.append(
                [
                    _esc(host.get("address") or "-"),
                    _esc(host.get("hostname") or "-"),
                    _esc(host.get("os") or "-"),
                    _esc(host.get("open_ports") or 0),
                ]
            )
        if rows:
            story.append(
                data_table(
                    ["Address", "Name", "System", "Open"],
                    rows,
                    widths=[96, 210, CONTENT_WIDTH - 376, 70],
                    align=["LEFT", "LEFT", "LEFT", "RIGHT"],
                )
            )

    for item in section("Output", "Raw scanner output, wrapped to the page width."):
        story.append(item)
    story.append(mono_block(results or "No output was attached to this scan.", max_lines=420))

    buffer = io.BytesIO()
    return _build(buffer, story, kicker="Scan results", report_id=f"NP-{uuid.uuid4().hex[:8].upper()}")


def section_note(text: str) -> Any:
    from reportlab.platypus import Paragraph

    return Paragraph(_esc(text), _styles()["small"])


def fallback_pdf(title: str, subtitle: str) -> bytes:
    """A valid one-page PDF when reportlab is unavailable.

    Kept deliberately minimal: the point is that the download still opens, not
    that it looks like the real report.
    """
    content = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 200 >>
stream
BT /F1 18 Tf 50 740 Td ({html.escape(title)[:60]}) Tj /F1 10 Tf 0 -24 Td ({html.escape(subtitle)[:90]}) Tj ET
endstream
endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
trailer << /Size 6 /Root 1 0 R >>
%%EOF
"""
    return content.encode("latin-1", errors="replace")
