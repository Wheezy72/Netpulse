from __future__ import annotations

import logging
from app.services.logging_service import memory_handler, LogEntry

def test_network_logs_filtering():
    # Clear any existing logs
    memory_handler.clear()

    # Add mock logs
    entries = [
        LogEntry(timestamp="2026-06-20T08:00:00Z", level="info", logger="app.tasks", message="Task started"),
        LogEntry(timestamp="2026-06-20T08:01:00Z", level="info", logger="uvicorn.access", message="GET /api/logs"),
        LogEntry(timestamp="2026-06-20T08:02:00Z", level="info", logger="netpulse.auth", message="User logged in"),
        LogEntry(timestamp="2026-06-20T08:03:00Z", level="info", logger="app.services.recon", message="Recon completed"),
    ]
    for entry in entries:
        memory_handler.logs.append(entry)

    # Get logs without level filtering (returns all)
    all_logs = memory_handler.get_logs()
    assert len(all_logs) == 4

    # Get logs with 'network' level filter (should return app.tasks and app.services.recon only)
    network_logs = memory_handler.get_logs(level="network")
    assert len(network_logs) == 2
    loggers = {log.logger for log in network_logs}
    assert loggers == {"app.tasks", "app.services.recon"}


def _emit(message: str, level: int = logging.INFO) -> None:
    """Push a record through the real emit path (seq assignment included)."""
    record = logging.LogRecord(
        name="test.logs",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    memory_handler.emit(record)


def test_entries_carry_a_monotonic_seq():
    """The viewer keys rows and cursors on seq, so every stored line needs one."""
    memory_handler.clear()

    for index in range(3):
        _emit(f"line {index}")

    stored = memory_handler.get_logs()
    assert len(stored) == 3
    seqs = [entry.seq for entry in stored]
    assert all(seq > 0 for seq in seqs)
    # Newest first, strictly decreasing.
    assert seqs == sorted(seqs, reverse=True)
    assert "seq" in stored[0].to_dict()


def test_since_seq_returns_only_newer_entries():
    """This is what makes a refresh append instead of redrawing the list."""
    memory_handler.clear()

    _emit("first")
    _emit("second")
    cursor = memory_handler.get_logs()[0].seq

    _emit("third")
    _emit("fourth")

    newer = memory_handler.get_logs(since_seq=cursor)
    assert [entry.message for entry in newer] == ["fourth", "third"]

    # Asking again from the newest id must yield nothing new.
    assert memory_handler.get_logs(since_seq=newer[0].seq) == []
