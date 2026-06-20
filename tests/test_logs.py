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
